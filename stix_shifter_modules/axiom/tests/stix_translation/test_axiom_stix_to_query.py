import re
import unittest

from stix_shifter.stix_translation import stix_translation
from stix_shifter_modules.axiom.stix_translation.query_constructor import apl_string, like_to_regex
from stix_shifter_modules.axiom.stix_translation.query_translator import merge_field_map, parse_field_map

MODULE = 'axiom'
translation = stix_translation.StixTranslation()
WINDOWS = {'dataset': 'huntbase-security', 'field_schema': 'windows'}
WINDOW = "START t'2026-11-02T12:00:00.000Z' STOP t'2026-11-02T12:30:00.000Z'"
TIME = "_time between (datetime(2026-11-02T12:00:00.000Z) .. datetime(2026-11-02T12:30:00.000Z))"


def ref(field):
    return f"tostring(column_ifexists('{field}', ''))"


def translate(pattern, options=None):
    result = translation.translate(MODULE, 'query', '{}', pattern, options or {})
    assert 'queries' in result, result
    return result['queries']


class TestAxiomStixToQuery(unittest.TestCase):

    def test_ipv4_ocsf_default(self):
        queries = translate(f"[ipv4-addr:value = '198.51.100.66'] {WINDOW}")
        self.assertEqual(queries, [
            f"['ocsf'] | where {TIME} | where "
            f"({ref('src_endpoint.ip')} =~ '198.51.100.66') or ({ref('dst_endpoint.ip')} =~ '198.51.100.66') "
            f"or ({ref('device.ip')} =~ '198.51.100.66')"
        ])

    def test_ipv4_windows_dataset(self):
        queries = translate(f"[ipv4-addr:value = '198.51.100.66'] {WINDOW}", WINDOWS)
        self.assertEqual(queries, [
            f"['huntbase-security'] | where {TIME} | where "
            f"({ref('SourceIp')} =~ '198.51.100.66') or ({ref('DestinationIp')} =~ '198.51.100.66') "
            f"or ({ref('IpAddress')} =~ '198.51.100.66')"
        ])

    def test_default_window_uses_time_range(self):
        queries = translate("[domain-name:value = 'bad.example']", {'time_range': 60})
        match = re.search(r"datetime\((\S+)Z\) \.\. datetime\((\S+)Z\)", queries[0])
        self.assertIsNotNone(match)
        from datetime import datetime
        start, stop = (datetime.fromisoformat(value) for value in match.groups())
        self.assertEqual((stop - start).total_seconds(), 3600)
        self.assertIn(f"{ref('query.hostname')} =~ 'bad.example'", queries[0])

    def test_file_hash_is_substring_match(self):
        sha = '0' * 58 + 'c0ffee'
        windows = translate(f"[file:hashes.'SHA-256' = '{sha}'] {WINDOW}", WINDOWS)[0]
        self.assertIn(f"{ref('Hashes')} contains '{sha}'", windows)
        ocsf = translate(f"[file:hashes.'SHA-256' = '{sha}'] {WINDOW}")[0]
        self.assertIn(f"{ref('file.hashes')} contains '{sha}'", ocsf)
        self.assertIn(f"{ref('process.file.hashes')} contains '{sha}'", ocsf)

    def test_process_name_matches_full_path(self):
        query = translate(f"[process:name = 'svc-upd.exe'] {WINDOW}", WINDOWS)[0]
        self.assertIn(f"{ref('Image')} =~ 'svc-upd.exe' or {ref('Image')} endswith '\\\\svc-upd.exe'", query)

    def test_user_matches_domain_qualified_account(self):
        query = translate(f"[user-account:user_id = 'jsmith'] {WINDOW}", WINDOWS)[0]
        self.assertIn(f"{ref('User')} endswith '\\\\jsmith'", query)
        self.assertIn(f"{ref('TargetUserName')} =~ 'jsmith'", query)

    def test_network_traffic_numeric_and_in(self):
        query = translate(f"[network-traffic:dst_port = 443 AND network-traffic:protocols[*] IN ('tcp', 'udp')] {WINDOW}",
                          WINDOWS)[0]
        self.assertIn(f"{ref('DestinationPort')} == '443'", query)
        self.assertIn(f"{ref('Protocol')} in~ ('tcp', 'udp')", query)
        self.assertIn(' and ', query)

    def test_greater_than_uses_toreal(self):
        query = translate(f"[network-traffic:dst_port > 1024] {WINDOW}")[0]
        self.assertIn("toreal(column_ifexists('dst_endpoint.port', '')) > 1024", query)

    def test_not_equal_and_negation(self):
        query = translate(f"[process:command_line != 'a'] {WINDOW}", WINDOWS)[0]
        self.assertIn(f"not({ref('CommandLine')} =~ 'a')", query)
        query = translate(f"[process:command_line NOT = 'a'] {WINDOW}", WINDOWS)[0]
        self.assertIn(f"not({ref('CommandLine')} =~ 'a')", query)

    def test_like_and_matches(self):
        query = translate(f"[process:command_line LIKE '%-enc%'] {WINDOW}", WINDOWS)[0]
        self.assertIn(f"{ref('CommandLine')} matches regex '(?i)^.*\\\\-enc.*$'", query)
        query = translate(f"[process:command_line MATCHES '^powershell'] {WINDOW}", WINDOWS)[0]
        self.assertIn(f"{ref('CommandLine')} matches regex '^powershell'", query)

    def test_cidr_issubset(self):
        query = translate(f"[ipv4-addr:value ISSUBSET '10.0.0.0/8'] {WINDOW}", WINDOWS)[0]
        self.assertIn(f"ipv4_is_in_range({ref('SourceIp')}, '10.0.0.0/8')", query)

    def test_backslashes_and_quotes_are_escaped(self):
        query = translate(f"[process:command_line = 'C:\\\\Users\\\\o\\'brien'] {WINDOW}", WINDOWS)[0]
        self.assertIn("=~ 'C:\\\\Users\\\\o\\'brien'", query)

    def test_observations_sharing_a_window_share_a_query(self):
        queries = translate(f"([ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'a.example']) {WINDOW}",
                            WINDOWS)
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0].count('_time between'), 1)

    def test_observations_with_different_windows_split(self):
        # Axiom rejects an "or" of time ranges, so each window gets a query.
        queries = translate(f"[ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'a.example'] {WINDOW}",
                            WINDOWS)
        self.assertEqual(len(queries), 2)
        self.assertTrue(all(query.count('_time between') == 1 for query in queries))

    def test_all_schemas_produce_one_query_each(self):
        queries = translate(f"[ipv4-addr:value = '1.2.3.4'] {WINDOW}", {'field_schema': 'all'})
        self.assertEqual(len(queries), 2)
        self.assertTrue(any('src_endpoint.ip' in query for query in queries))
        self.assertTrue(any('SourceIp' in query for query in queries))

    def test_field_map_option_adds_fields(self):
        options = dict(WINDOWS, field_map='{"ipv4-addr": {"fields": {"value": ["client_ip"]}}}')
        query = translate(f"[ipv4-addr:value = '1.2.3.4'] {WINDOW}", options)[0]
        self.assertIn(f"{ref('client_ip')} =~ '1.2.3.4'", query)
        self.assertIn(f"{ref('SourceIp')} =~ '1.2.3.4'", query)

    def test_field_map_maps_unknown_object(self):
        options = dict(WINDOWS, field_map={"x-custom": {"fields": {"tag": ["Tag"]}}})
        query = translate(f"[x-custom:tag = 'red'] {WINDOW}", options)[0]
        self.assertIn(f"{ref('Tag')} =~ 'red'", query)

    def test_unmapped_attribute_is_an_error(self):
        result = translation.translate(MODULE, 'query', '{}', "[software:name = 'x']", {})
        self.assertFalse(result.get('success', True))

    def test_bad_dataset_name_rejected(self):
        result = translation.translate(MODULE, 'query', '{}', "[ipv4-addr:value = '1.2.3.4']",
                                       {'dataset': "x'] | delete"})
        self.assertFalse(result.get('success', True))

    def test_helpers(self):
        self.assertEqual(apl_string("a'b\\c"), "'a\\'b\\\\c'")
        self.assertEqual(like_to_regex('a%b_c'), '(?i)^a.*b.c$')

    def test_parse_and_merge_field_map(self):
        self.assertEqual(parse_field_map(None), {})
        with self.assertRaises(ValueError):
            parse_field_map('{not json')
        with self.assertRaises(ValueError):
            parse_field_map({'ipv4-addr': {'fields': {'value': 'not-a-list'}}})
        merged = merge_field_map({'ipv4-addr': {'fields': {'value': ['a']}}},
                                 {'ipv4-addr': {'fields': {'value': ['a', 'b']}}})
        self.assertEqual(merged['ipv4-addr']['fields']['value'], ['a', 'b'])
