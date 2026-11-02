import unittest

from stix_shifter_modules.axiom.entry_point import EntryPoint
from stix_shifter_modules.axiom.stix_translation.results_translator import normalise_row, unflatten
from stix_shifter_utils.stix_translation.src.utils.transformer_utils import get_module_transformers
from stix_shifter_utils.stix_translation.src.json_to_stix import json_to_stix_translator

MODULE = 'axiom'
entry_point = EntryPoint()
translator = entry_point.get_results_translator()
transformers = get_module_transformers(MODULE)
DATA_SOURCE = {
    'type': 'identity',
    'id': 'identity--3532c56d-ea72-48be-a2ad-1a53f4c9c6d3',
    'name': 'Axiom',
    'identity_class': 'events',
}

# Shapes as Axiom's tabular API returns them (dotted OCSF columns, flat Windows fields).
SYSMON_PROCESS = {
    '_time': '2026-11-02T12:11:05.357227Z',
    'EventID': 1,
    'Channel': 'Microsoft-Windows-Sysmon/Operational',
    'Hostname': 'wks-fin-07.baselab.example.org',
    'Image': 'C:\\Users\\Public\\svc-upd.exe',
    'CommandLine': 'C:\\Users\\Public\\svc-upd.exe -k netsvc',
    'ParentImage': 'C:\\Windows\\explorer.exe',
    'Hashes': 'SHA256=0000000000000000000000000000000000000000000000000000000000C0FFEE,MD5=0123456789abcdef0123456789abcdef',
    'User': 'BASELAB\\jsmith',
}
SYSMON_NETWORK = {
    '_time': '2026-11-02T12:11:00.357227Z',
    'EventID': 3,
    'Hostname': 'wks-fin-07.baselab.example.org',
    'DestinationIp': '198.51.100.66',
    'DestinationPort': '443',
    'Protocol': 'tcp',
}
OCSF_NETWORK = {
    '_time': '2026-11-02T12:11:00.357Z',
    'class_uid': 4001,
    'class_name': 'Network Activity',
    'activity_name': 'Open',
    'src_endpoint.ip': '10.1.2.3',
    'src_endpoint.port': 51515,
    'dst_endpoint.ip': '198.51.100.66',
    'dst_endpoint.port': 443,
    'connection_info.protocol_name': 'TCP',
    'device.hostname': 'wks-fin-07',
}
OCSF_PROCESS = {
    '_time': '2026-11-02T12:11:05.357Z',
    'class_uid': 1007,
    'process.name': 'svc-upd.exe',
    'process.pid': 4242,
    'process.cmd_line': 'svc-upd.exe -k netsvc',
    'process.file.name': 'svc-upd.exe',
    'process.file.parent_folder': 'C:\\Users\\Public',
    'process.file.hashes': [{'algorithm': 'SHA-256', 'algorithm_id': 3, 'value': 'abc123'},
                            {'algorithm_id': 1, 'value': 'def456'}],
    'actor.user.name': 'jsmith',
}


def to_stix(row):
    bundle = json_to_stix_translator.convert_to_stix(DATA_SOURCE, translator.map_data, [normalise_row(row)],
                                                     transformers, {})
    observed = bundle['objects'][1]
    return observed, observed['objects']


def find(objects, stix_type):
    return [obj for obj in objects.values() if obj['type'] == stix_type]


class TestAxiomJsonToStix(unittest.TestCase):

    def test_unflatten(self):
        self.assertEqual(unflatten({'a.b': 1, 'a.c': 2, '_time': 't', 'x': 3}),
                         {'a': {'b': 1, 'c': 2}, '_time': 't', 'x': 3})
        # a dotted key that clashes with a scalar stays flat
        self.assertEqual(unflatten({'a': 1, 'a.b': 2}), {'a': 1, 'a.b': 2})

    def test_sysmon_process(self):
        observed, objects = to_stix(SYSMON_PROCESS)
        self.assertEqual(observed['first_observed'], '2026-11-02T12:11:05.357227Z')
        files = find(objects, 'file')
        self.assertEqual(files[0]['name'], 'svc-upd.exe')
        self.assertEqual(files[0]['hashes'], {'SHA-256': '0' * 58 + 'c0ffee',
                                              'MD5': '0123456789abcdef0123456789abcdef'})
        processes = {p.get('command_line'): p for p in find(objects, 'process')}
        child = processes['C:\\Users\\Public\\svc-upd.exe -k netsvc']
        self.assertEqual(child['name'], 'svc-upd.exe')
        self.assertEqual(objects[child['parent_ref']]['name'], 'explorer.exe')
        self.assertEqual(objects[child['creator_user_ref']]['user_id'], 'jsmith')
        self.assertEqual(find(objects, 'directory')[0]['path'], 'C:\\Users\\Public')
        self.assertEqual(find(objects, 'x-oca-event')[0]['code'], 1)

    def test_sysmon_network(self):
        _, objects = to_stix(SYSMON_NETWORK)
        traffic = find(objects, 'network-traffic')[0]
        self.assertEqual(traffic['dst_port'], 443)
        self.assertEqual(traffic['protocols'], ['tcp'])
        self.assertEqual(objects[traffic['dst_ref']]['value'], '198.51.100.66')
        self.assertEqual(find(objects, 'x-oca-asset')[0]['hostname'], 'wks-fin-07.baselab.example.org')

    def test_ocsf_network(self):
        _, objects = to_stix(OCSF_NETWORK)
        traffic = find(objects, 'network-traffic')[0]
        self.assertEqual(objects[traffic['src_ref']]['value'], '10.1.2.3')
        self.assertEqual(objects[traffic['dst_ref']]['value'], '198.51.100.66')
        self.assertEqual((traffic['src_port'], traffic['dst_port']), (51515, 443))
        self.assertEqual(traffic['protocols'], ['tcp'])
        event = find(objects, 'x-oca-event')[0]
        self.assertEqual((event['code'], event['module'], event['action']), (4001, 'Network Activity', 'Open'))

    def test_ocsf_process_with_hashes(self):
        _, objects = to_stix(OCSF_PROCESS)
        process = find(objects, 'process')[0]
        self.assertEqual((process['name'], process['pid']), ('svc-upd.exe', 4242))
        binary = objects[process['binary_ref']]
        self.assertEqual(binary['hashes'], {'SHA-256': 'abc123', 'MD5': 'def456'})
        self.assertEqual(objects[binary['parent_directory_ref']]['path'], 'C:\\Users\\Public')
        self.assertEqual(find(objects, 'user-account')[0]['user_id'], 'jsmith')

    def test_translate_results_accepts_json_strings(self):
        import json
        from stix_shifter.stix_translation import stix_translation
        result = stix_translation.StixTranslation().translate(
            MODULE, 'results', json.dumps(DATA_SOURCE), json.dumps([SYSMON_NETWORK, OCSF_NETWORK]), {})
        self.assertEqual(result['type'], 'bundle')
        self.assertEqual(len(result['objects']), 3)
