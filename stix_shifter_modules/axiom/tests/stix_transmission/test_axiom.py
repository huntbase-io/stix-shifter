import json
import unittest
from unittest.mock import patch

from stix_shifter.stix_transmission import stix_transmission
from stix_shifter_modules.axiom.stix_transmission.connector import query_window, tabular_to_rows
from tests.utils.async_utils import get_mock_response

CONNECTION = {'host': 'api.axiom.co', 'port': 443, 'options': {'dataset': 'huntbase-security'}}
CONFIGURATION = {'auth': {'api_key': 'xaat-test'}}
CALL_API = 'stix_shifter_utils.stix_transmission.utils.RestApiClientAsync.RestApiClientAsync.call_api'
QUERY = ("['huntbase-security'] | where _time between (datetime(2026-11-02T12:00:00.000Z) .. "
         "datetime(2026-11-02T12:30:00.000Z)) | where tostring(column_ifexists('DestinationIp', '')) =~ '198.51.100.66'")
TABULAR = {
    'format': 'tabular',
    'tables': [{
        'name': '0',
        'fields': [{'name': '_time', 'type': 'datetime'}, {'name': 'DestinationIp', 'type': 'string'},
                   {'name': 'DestinationPort', 'type': 'string'}, {'name': 'QueryName', 'type': 'string'}],
        'columns': [['2026-11-02T12:11:00.357227Z', '2026-11-02T12:10:55.357227Z'],
                    ['198.51.100.66', None],
                    ['443', None],
                    [None, 'update-check.bad-actor.example']],
    }],
}


def transmission(connection=None):
    return stix_transmission.StixTransmission('axiom', connection or CONNECTION, CONFIGURATION)


class TestAxiomTransmission(unittest.TestCase):

    def test_tabular_to_rows_drops_nulls(self):
        self.assertEqual(tabular_to_rows(TABULAR), [
            {'_time': '2026-11-02T12:11:00.357227Z', 'DestinationIp': '198.51.100.66', 'DestinationPort': '443'},
            {'_time': '2026-11-02T12:10:55.357227Z', 'QueryName': 'update-check.bad-actor.example'},
        ])

    def test_query_window_from_query(self):
        self.assertEqual(query_window(QUERY), ('2026-11-02T12:00:00.000Z', '2026-11-02T12:30:01.000Z'))

    def test_query_window_default(self):
        start, stop = query_window("['x'] | take 1", 10)
        self.assertLess(start, stop)

    @patch(CALL_API)
    def test_ping(self, mock_api):
        mock_api.return_value = get_mock_response(200, json.dumps({'name': 'huntbase-security'}), 'byte')
        self.assertEqual(transmission().ping(), {'success': True})
        endpoint, method = mock_api.call_args.args[:2]
        self.assertEqual((endpoint, method), ('v2/datasets/huntbase-security', 'GET'))

    @patch(CALL_API)
    def test_ping_unknown_dataset(self, mock_api):
        mock_api.return_value = get_mock_response(404, json.dumps({'code': 404, 'message': 'not found'}), 'byte')
        result = transmission().ping()
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'invalid_parameter')
        self.assertIn('huntbase-security', result['error'])

    @patch(CALL_API)
    def test_ping_bad_token(self, mock_api):
        mock_api.return_value = get_mock_response(403, json.dumps({'code': 403, 'message': 'Forbidden'}), 'byte')
        result = transmission().ping()
        self.assertEqual(result['code'], 'authentication_fail')

    def test_query_returns_search_id(self):
        result = transmission().query(QUERY)
        self.assertEqual(result, {'success': True, 'search_id': QUERY})

    def test_status_is_complete(self):
        result = transmission().status(QUERY)
        self.assertEqual(result['status'], 'COMPLETED')

    @patch(CALL_API)
    def test_results(self, mock_api):
        mock_api.return_value = get_mock_response(200, json.dumps(TABULAR), 'byte')
        result = transmission().results(QUERY, 0, 10)
        self.assertTrue(result['success'])
        self.assertEqual(len(result['data']), 2)
        endpoint, method = mock_api.call_args.args[:2]
        self.assertEqual((endpoint, method), ('v1/datasets/_apl', 'POST'))
        body = json.loads(mock_api.call_args.kwargs['data'])
        self.assertEqual(body['apl'], QUERY + ' | sort by _time desc | take 10')
        self.assertEqual((body['startTime'], body['endTime']), ('2026-11-02T12:00:00.000Z', '2026-11-02T12:30:01.000Z'))
        self.assertEqual(mock_api.call_args.kwargs['urldata'], {'format': 'tabular'})

    @patch(CALL_API)
    def test_results_offset(self, mock_api):
        mock_api.return_value = get_mock_response(200, json.dumps(TABULAR), 'byte')
        result = transmission().results(QUERY, 1, 5)
        self.assertEqual(len(result['data']), 1)
        body = json.loads(mock_api.call_args.kwargs['data'])
        self.assertTrue(body['apl'].endswith('| take 6'))

    @patch(CALL_API)
    def test_results_respects_result_limit(self, mock_api):
        mock_api.return_value = get_mock_response(200, json.dumps(TABULAR), 'byte')
        connection = {**CONNECTION, 'options': {**CONNECTION['options'], 'result_limit': 3}}
        transmission(connection).results(QUERY, 0, 100)
        body = json.loads(mock_api.call_args.kwargs['data'])
        self.assertTrue(body['apl'].endswith('| take 3'))

    @patch(CALL_API)
    def test_results_query_error(self, mock_api):
        error = {'code': 400, 'message': 'invalid field', 'detail': {'message': 'invalid field: "x"'}}
        mock_api.return_value = get_mock_response(400, json.dumps(error), 'byte')
        result = transmission().results(QUERY, 0, 10)
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'invalid_query')
        self.assertIn('invalid field: "x"', result['error'])

    @patch(CALL_API)
    def test_results_query_limit(self, mock_api):
        mock_api.return_value = get_mock_response(430, json.dumps({'code': 430, 'message': 'query limit'}), 'byte')
        result = transmission().results(QUERY, 0, 10)
        self.assertEqual(result['code'], 'too_many_requests')

    @patch(CALL_API)
    def test_results_connection_error(self, mock_api):
        mock_api.side_effect = Exception('client_connector_error: (boom)')
        result = transmission().results(QUERY, 0, 10)
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'service_unavailable')

    def test_org_id_header(self):
        from stix_shifter_modules.axiom.stix_transmission.api_client import APIClient
        client = APIClient({**CONNECTION, 'org_id': 'huntbase-inju'}, CONFIGURATION)
        self.assertEqual(client.headers['X-AXIOM-ORG-ID'], 'huntbase-inju')
        self.assertEqual(client.headers['Authorization'], 'Bearer xaat-test')
