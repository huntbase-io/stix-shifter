import json
import re

from stix_shifter_utils.stix_translation.src.json_to_stix.json_to_stix import JSONToStix

# OCSF fingerprint algorithm names -> the key used under ``<object>.hashes_by_algorithm``.
_OCSF_ALGORITHMS = {
    'md5': 'MD5',
    'sha-1': 'SHA-1',
    'sha1': 'SHA-1',
    'sha-256': 'SHA-256',
    'sha256': 'SHA-256',
    'sha-512': 'SHA-512',
    'sha512': 'SHA-512',
}
# OCSF fingerprint algorithm_id values (OCSF 1.x fingerprint object).
_OCSF_ALGORITHM_IDS = {1: 'MD5', 2: 'SHA-1', 3: 'SHA-256', 4: 'SHA-512'}


def unflatten(row: dict) -> dict:
    """Turn Axiom's dotted column names back into nested objects.

    Axiom flattens nested JSON at ingest (``src_endpoint.ip``); the to_stix map
    follows the nested OCSF shape. A key that would clash with an existing
    scalar (``process`` and ``process.pid``) is kept flat.
    """
    nested: dict = {}
    for key, value in row.items():
        parts = key.split('.') if isinstance(key, str) and not key.startswith('_') else [key]
        cursor = nested
        clash = False
        for part in parts[:-1]:
            child = cursor.get(part)
            if child is None:
                child = cursor[part] = {}
            elif not isinstance(child, dict):
                clash = True
                break
            cursor = child
        if clash or (parts[-1] in cursor and isinstance(cursor[parts[-1]], dict)):
            nested[key] = value
        else:
            cursor[parts[-1]] = value
    return nested


def _hashes_by_algorithm(value) -> dict:
    """OCSF ``hashes`` (a list of fingerprint objects) as ``{"SHA-256": "..."}``."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return {}
    out = {}
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, dict) or not item.get('value'):
            continue
        name = _OCSF_ALGORITHMS.get(str(item.get('algorithm', '')).lower()) or \
            _OCSF_ALGORITHM_IDS.get(item.get('algorithm_id'))
        if name:
            out[name] = item['value']
    return out


_SYSMON_HASH = re.compile(r'(MD5|SHA1|SHA256|IMPHASH)=([0-9A-Fa-f]+)')
_SYSMON_ALGORITHMS = {'MD5': 'MD5', 'SHA1': 'SHA-1', 'SHA256': 'SHA-256'}


def _sysmon_hashes(value) -> dict:
    """Sysmon ``Hashes`` (``SHA256=ab12...,MD5=...``) as ``{"SHA-256": "ab12..."}``."""
    out = {}
    for name, digest in _SYSMON_HASH.findall(str(value or '')):
        if name.upper() in _SYSMON_ALGORITHMS:
            out[_SYSMON_ALGORITHMS[name.upper()]] = digest.lower()
    return out


def normalise_row(row: dict) -> dict:
    """Prepare one Axiom row for the to_stix maps.

    * dotted OCSF columns become nested objects;
    * OCSF ``hashes`` lists and Sysmon ``Hashes`` strings become
      ``hashes_by_algorithm`` / ``HashesByAlgorithm`` dicts keyed by STIX
      hash names, so each digest maps to its own STIX hash key.
    """
    if isinstance(row.get('Hashes'), str):
        row = dict(row)
        row['HashesByAlgorithm'] = _sysmon_hashes(row.pop('Hashes'))
    row = unflatten(row)
    process = row.get('process') if isinstance(row.get('process'), dict) else {}
    for parent in (row.get('file'), process.get('file')):
        if isinstance(parent, dict) and 'hashes' in parent:
            parent['hashes_by_algorithm'] = _hashes_by_algorithm(parent.pop('hashes'))
    return row


class ResultsTranslator(JSONToStix):

    def translate_results(self, data_source, data):
        if isinstance(data_source, str):
            data_source = json.loads(data_source)
        if isinstance(data, str):
            data = json.loads(data)
        rows = [normalise_row(row) if isinstance(row, dict) else row for row in (data or [])]
        return super().translate_results(data_source, rows)
