import json
from urllib.parse import quote

from stix_shifter_utils.stix_transmission.utils.RestApiClientAsync import RestApiClientAsync


class APIClient:
    """Thin client for the Axiom query API.

    Queries always go to the API host (``api.axiom.co``), whatever region the
    dataset lives in; only ingest needs the regional edge domain.
    """
    QUERY_ENDPOINT = 'v1/datasets/_apl'
    DATASETS_ENDPOINT = 'v2/datasets'

    def __init__(self, connection, configuration):
        auth = configuration.get('auth') or {}
        options = connection.get('options') or {}
        self.headers = {
            'Authorization': f"Bearer {auth.get('api_key', '')}",
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        if connection.get('org_id'):
            self.headers['X-AXIOM-ORG-ID'] = connection['org_id']
        port = connection.get('port')
        self.client = RestApiClientAsync(connection.get('host'), port=None if port in (None, 443) else port,
                                         headers=self.headers)
        self.timeout = options.get('timeout')
        self.result_limit = options.get('result_limit')
        self.dataset = options.get('dataset')

    async def ping_data_source(self):
        """GET the configured dataset (or the dataset list): checks host, token and dataset access."""
        endpoint = self.DATASETS_ENDPOINT
        if self.dataset:
            endpoint += '/' + quote(str(self.dataset), safe='')
        return await self.client.call_api(endpoint, 'GET', timeout=self.timeout)

    async def run_query(self, apl, start_time, end_time):
        """POST an APL query and return the tabular response."""
        body = {'apl': apl, 'startTime': start_time, 'endTime': end_time}
        return await self.client.call_api(self.QUERY_ENDPOINT, 'POST', data=json.dumps(body),
                                          urldata={'format': 'tabular'}, timeout=self.timeout)
