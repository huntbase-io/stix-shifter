import json
import re
from datetime import datetime, timedelta, timezone

from stix_shifter_utils.modules.base.stix_transmission.base_json_sync_connector import BaseJsonSyncConnector
from stix_shifter_utils.utils import logger
from stix_shifter_utils.utils.error_response import ErrorResponder

from .api_client import APIClient

_DATETIME = re.compile(r"datetime\((\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\)")
# Axiom caps a single tabular response; page with ``take`` inside this.
MAX_ROWS_PER_QUERY = 50000


def _parse(value):
    text = value.rstrip('Z')
    fmt = '%Y-%m-%dT%H:%M:%S.%f' if '.' in text else '%Y-%m-%dT%H:%M:%S'
    return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)


def _iso(value):
    return value.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def query_window(apl, default_minutes=5):
    """The ``startTime``/``endTime`` to send with ``apl``.

    The translated query carries its windows as ``_time between (datetime(a) ..
    datetime(b))``; Axiom also needs the outer window in the request body (it
    prunes storage blocks with it). Use the earliest start and latest stop, with
    one second of slack because ``endTime`` is exclusive. A hand-written query
    without datetimes gets the last ``default_minutes``.
    """
    stamps = [_parse(match) for match in _DATETIME.findall(apl or '')]
    if stamps:
        return _iso(min(stamps)), _iso(max(stamps) + timedelta(seconds=1))
    stop = datetime.now(timezone.utc)
    return _iso(stop - timedelta(minutes=default_minutes)), _iso(stop)


def tabular_to_rows(payload):
    """Axiom ``format=tabular`` (column-major) as a list of row dicts, nulls dropped."""
    rows = []
    for table in payload.get('tables') or []:
        names = [field.get('name') for field in table.get('fields') or []]
        columns = table.get('columns') or []
        count = max((len(column) for column in columns), default=0)
        for index in range(count):
            row = {}
            for name, column in zip(names, columns):
                value = column[index] if index < len(column) else None
                if value is not None and value != '':
                    row[name] = value
            if row:
                rows.append(row)
    return rows


class Connector(BaseJsonSyncConnector):

    def __init__(self, connection, configuration):
        self.api_client = APIClient(connection, configuration)
        self.time_range = (connection.get('options') or {}).get('time_range') or 5
        self.logger = logger.set_logger(__name__)
        self.connector = __name__.split('.')[1]

    def _error(self, code, message):
        if code in (401, 403):
            # stix-shifter classifies by message text before the error mapper runs.
            message = f"Not authorized: Axiom rejected the API token or its dataset access ({message})"
        return_obj = {}
        ErrorResponder.fill_error(return_obj, {'code': code, 'message': message}, ['message'],
                                  connector=self.connector)
        return return_obj

    @staticmethod
    def _message(response, default):
        try:
            body = json.loads(response.read() or b'{}')
        except (ValueError, TypeError):
            return default
        detail = body.get('detail') if isinstance(body.get('detail'), dict) else {}
        return detail.get('message') or body.get('message') or default

    async def ping_connection(self):
        try:
            response = await self.api_client.ping_data_source()
            if 200 <= response.code < 300:
                return {'success': True}
            if response.code == 404:
                return self._error(404, f"Dataset not found: {self.api_client.dataset}")
            return self._error(response.code, self._message(response, f'Ping failed with HTTP {response.code}'))
        except Exception as ex:
            self.logger.error('error when pinging Axiom: %s', ex)
            return self._error(self._exception_code(ex), str(ex))

    async def create_results_connection(self, query, offset, length):
        """Run the APL query and return rows ``offset`` .. ``offset + length``.

        Axiom has no offset, so the query asks for ``offset + length`` rows
        (newest first, within ``result_limit``) and the head is dropped.
        """
        try:
            offset, length = int(offset), int(length)
            wanted = offset + length
            if self.api_client.result_limit:
                wanted = min(wanted, int(self.api_client.result_limit))
            wanted = min(wanted, MAX_ROWS_PER_QUERY)
            if wanted <= offset:
                return {'success': True, 'data': []}
            start_time, end_time = query_window(query, self.time_range)
            apl = f"{query} | sort by _time desc | take {wanted}"
            response = await self.api_client.run_query(apl, start_time, end_time)
            if response.code != 200:
                return self._error(response.code, self._message(response, f'Query failed with HTTP {response.code}'))
            payload = json.loads(response.read())
            rows = tabular_to_rows(payload)
            return {'success': True, 'data': rows[offset:wanted]}
        except Exception as ex:
            self.logger.error('error when running Axiom query: %s', ex)
            return self._error(self._exception_code(ex), str(ex))

    @staticmethod
    def _exception_code(ex):
        text = str(ex)
        if 'too_many_requests' in text:
            return 429
        if 'timeout_error' in text:
            return 408
        return 503 if 'client_connector_error' in text else None
