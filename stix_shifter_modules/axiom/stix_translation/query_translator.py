import copy
import json

from stix_shifter_utils.modules.base.stix_translation.base_query_translator import BaseQueryTranslator
from stix_shifter_utils.utils import logger as utils_logger
from . import query_constructor


def parse_field_map(value):
    """Parse the ``field_map`` option: a from_stix map fragment as JSON or a dict.

    Shape: ``{"<stix object>": {"fields": {"<property>": ["<dataset field>", ...]}}}``.
    Anything else raises ``ValueError`` so a bad option fails loudly.
    """
    if value in (None, '', {}):
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as ex:
            raise ValueError(f'field_map is not valid JSON: {ex.msg}') from ex
    if not isinstance(value, dict):
        raise ValueError('field_map must be a JSON object')
    for stix_object, spec in value.items():
        fields = spec.get('fields') if isinstance(spec, dict) else None
        if not isinstance(fields, dict):
            raise ValueError(f'field_map entry {stix_object!r} needs a "fields" object')
        for prop, targets in fields.items():
            if not isinstance(targets, list) or not all(isinstance(t, str) and t for t in targets):
                raise ValueError(f'field_map {stix_object}:{prop} must be a list of field names')
    return value


def merge_field_map(base, extra):
    """Add ``extra``'s dataset fields to ``base`` (a from_stix map), keeping order and no duplicates."""
    merged = copy.deepcopy(base)
    for stix_object, spec in extra.items():
        target = merged.setdefault(stix_object, {'fields': {}}).setdefault('fields', {})
        for prop, fields in spec['fields'].items():
            existing = target.setdefault(prop, [])
            for field in fields:
                if field not in existing:
                    existing.append(field)
    return merged


class QueryTranslator(BaseQueryTranslator):

    def __init__(self, options, dialect, basepath):
        super().__init__(options, dialect, basepath)
        self.logger = utils_logger.set_logger(__name__)
        extra = parse_field_map((options or {}).get('field_map'))
        if extra:
            self.map_data = merge_field_map(self.map_data, extra)

    def transform_antlr(self, data, antlr_parsing_object):
        """Translate a parsed STIX pattern into one APL query."""
        self.logger.info("Converting STIX2 Pattern to Axiom APL")
        return query_constructor.translate_pattern(antlr_parsing_object, self, self.options)
