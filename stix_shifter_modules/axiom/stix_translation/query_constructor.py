"""STIX pattern -> Axiom Processing Language (APL).

One pattern becomes one APL query over one dataset:

    ['<dataset>']
    | where _time between (datetime(<start>) .. datetime(<stop>))
    | where (<observation 1>) or (<observation 2>)

Design notes:

* Every dataset field is read through ``column_ifexists('<field>', '')``. Axiom
  fails the whole query with "invalid field" when a column does not exist,
  and Axiom datasets are sparse (a column appears only once an event fills
  it). With the guard, one mapping fits datasets that hold only some of the
  mapped columns.
* String comparisons go through ``tostring()`` so a numeric value such as a
  port matches whether the dataset stores it as a number or a string.
* Equality on strings is case-insensitive (``=~``): hostnames, Windows paths
  and account names are case-insensitive in practice.
* ``config_map.json`` lists, per field layout (dialect), fields that need
  special handling: ``substring_fields`` (match inside a composite value, e.g.
  Sysmon ``Hashes`` "SHA256=...,MD5=..." or OCSF ``file.hashes``) and
  ``basename_fields`` (full paths or DOMAIN\\user values that a bare name
  should match, e.g. ``process:name = 'svc.exe'`` against ``Image``).
* Each observation keeps its own time window. Without a START/STOP qualifier
  the window is the last ``options.time_range`` minutes. Axiom rejects an
  ``or`` of time ranges, so observations that share a window share a query
  and each distinct window gets its own query (stix-shifter runs them all).
"""

import json
import re
from datetime import datetime, timedelta, timezone
from os import path

from stix_shifter_utils.stix_translation.src.patterns.pattern_objects import (
    CombinedComparisonExpression,
    CombinedObservationExpression,
    ComparisonComparators,
    ComparisonExpression,
    ComparisonExpressionOperators,
    ObservationExpression,
    Pattern,
    StartStopQualifier,
)

CONFIG_MAP_PATH = path.join(path.dirname(path.abspath(__file__)), 'json', 'config_map.json')
TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z")
DATASET_PATTERN = re.compile(r"^[A-Za-z0-9._\-]+$")
DEFAULT_TIME_RANGE_MINUTES = 5


def _load_config_map():
    with open(CONFIG_MAP_PATH, encoding='utf-8') as handle:
        return json.load(handle)


def apl_string(value) -> str:
    """Quote ``value`` as an APL string literal."""
    text = str(value).replace('\\', '\\\\').replace("'", "\\'")
    return f"'{text}'"


def apl_field(field: str) -> str:
    """A null-safe reference to a dataset field (see module docstring)."""
    return f"column_ifexists({apl_string(field)}, '')"


def apl_datetime(value: datetime) -> str:
    return f"datetime({value.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z)"


def like_to_regex(value: str) -> str:
    """STIX LIKE (``%`` any run, ``_`` one char) as an anchored, case-insensitive RE2 regex."""
    out = []
    for char in str(value):
        if char == '%':
            out.append('.*')
        elif char == '_':
            out.append('.')
        else:
            out.append(re.escape(char))
    return '(?i)^' + ''.join(out) + '$'


def _unescape(value):
    """Undo STIX quote escaping the pattern parser leaves in (it only unescapes ``\\\\``)."""
    if isinstance(value, str):
        return value.replace("\\'", "'")
    if hasattr(value, 'values'):
        return [_unescape(item) for item in value.values]
    return value


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _parse_timestamp(value: str) -> datetime:
    text = value.strip("t'").rstrip('Z')
    fmt = '%Y-%m-%dT%H:%M:%S.%f' if '.' in text else '%Y-%m-%dT%H:%M:%S'
    return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)


class AplQueryBuilder:

    def __init__(self, pattern: Pattern, translator, options: dict):
        self.translator = translator
        self.options = options or {}
        layouts = _load_config_map()
        self.layout = layouts.get(translator.dialect, {})
        self.substring_fields = set(self.layout.get('substring_fields', []))
        self.basename_fields = set(self.layout.get('basename_fields', []))
        # time clause -> observation conditions, in pattern order
        self.observations = {}
        self._window = None
        self._walk(pattern.expression if isinstance(pattern, Pattern) else pattern)

    # ---- time -------------------------------------------------------------

    @property
    def _default_window(self):
        if self._window is not None:
            return self._window
        minutes = self.options.get('time_range') or DEFAULT_TIME_RANGE_MINUTES
        stop = datetime.now(timezone.utc)
        self._window = (stop - timedelta(minutes=int(minutes)), stop)
        return self._window

    def _time_clause(self, qualifier) -> str:
        if qualifier is not None:
            start, stop = _parse_timestamp(qualifier.start), _parse_timestamp(qualifier.stop)
        else:
            start, stop = self._default_window
        return f"_time between ({apl_datetime(start)} .. {apl_datetime(stop)})"

    # ---- pattern tree ------------------------------------------------------

    def _walk(self, expression, qualifier=None):
        if isinstance(expression, StartStopQualifier):
            self._walk(expression.observation_expression, expression)
        elif isinstance(expression, CombinedObservationExpression):
            # FOLLOWEDBY/AND across observations are run as OR: each observation
            # matches its own events, as in other stix-shifter search connectors.
            self._walk(expression.expr1, qualifier)
            self._walk(expression.expr2, qualifier)
        elif isinstance(expression, ObservationExpression):
            condition = self._comparison(expression.comparison_expression)
            if condition:
                self.observations.setdefault(self._time_clause(qualifier), []).append(condition)
        elif hasattr(expression, 'observation_expression'):
            # Other qualifiers (REPEATS, WITHIN) are not supported by a search
            # API; keep the observation with its default window.
            self._walk(expression.observation_expression, qualifier)
        else:
            raise RuntimeError(f"Unknown expression {expression!r} of type {type(expression)}")

    def _comparison(self, expression) -> str:
        if isinstance(expression, CombinedComparisonExpression):
            left = self._comparison(expression.expr1)
            right = self._comparison(expression.expr2)
            if not left or not right:
                return left or right
            operator = 'and' if expression.operator == ComparisonExpressionOperators.And else 'or'
            return f"({left}) {operator} ({right})"
        if isinstance(expression, ComparisonExpression):
            return self._leaf(expression)
        raise RuntimeError(f"Unknown comparison {expression!r}")

    # ---- leaves ------------------------------------------------------------

    def _leaf(self, expression: ComparisonExpression) -> str:
        stix_object, stix_property = expression.object_path.split(':', 1)
        fields = self.translator.map_field(stix_object, stix_property)
        if not fields:
            return ''
        comparator = expression.comparator
        negate = expression.negated
        if comparator == ComparisonComparators.NotEqual:
            comparator, negate = ComparisonComparators.Equal, not negate

        value = _unescape(expression.value)
        parts = [self._field_condition(field, comparator, value) for field in fields]
        condition = parts[0] if len(parts) == 1 else ' or '.join(f"({part})" for part in parts)
        if negate:
            condition = f"not({condition})"
        return condition

    def _field_condition(self, field: str, comparator, value) -> str:
        ref = apl_field(field)
        text = f"tostring({ref})"
        if comparator == ComparisonComparators.Equal:
            return self._equals(field, text, value)
        if comparator == ComparisonComparators.In:
            values = list(getattr(value, 'values', value))
            if field in self.substring_fields or field in self.basename_fields:
                return ' or '.join(f"({self._equals(field, text, item)})" for item in values)
            return f"{text} in~ ({', '.join(apl_string(item) for item in values)})"
        if comparator == ComparisonComparators.Like:
            regex = like_to_regex(value)
            if field in self.basename_fields:
                regex = regex.replace('(?i)^', '(?i)^(?:.*\\\\)?', 1)
            return f"{text} matches regex {apl_string(regex)}"
        if comparator == ComparisonComparators.Matches:
            return f"{text} matches regex {apl_string(value)}"
        if comparator in (ComparisonComparators.GreaterThan, ComparisonComparators.GreaterThanOrEqual,
                          ComparisonComparators.LessThan, ComparisonComparators.LessThanOrEqual):
            operator = {
                ComparisonComparators.GreaterThan: '>',
                ComparisonComparators.GreaterThanOrEqual: '>=',
                ComparisonComparators.LessThan: '<',
                ComparisonComparators.LessThanOrEqual: '<=',
            }[comparator]
            if _is_number(value):
                return f"toreal({ref}) {operator} {value}"
            if isinstance(value, str) and TIMESTAMP_PATTERN.fullmatch(value.strip("t'")):
                return f"todatetime({ref}) {operator} {apl_datetime(_parse_timestamp(value))}"
            return f"{text} {operator} {apl_string(value)}"
        if comparator in (ComparisonComparators.IsSubSet, ComparisonComparators.IsSuperSet):
            # ipv4-addr:value ISSUBSET '10.0.0.0/8'
            return f"ipv4_is_in_range({text}, {apl_string(value)})"
        raise NotImplementedError(f"Comparison operator {comparator.name} is not supported for Axiom")

    def _equals(self, field: str, text: str, value) -> str:
        if _is_number(value):
            return f"{text} == {apl_string(value)}"
        if field in self.substring_fields:
            return f"{text} contains {apl_string(value)}"
        if field in self.basename_fields:
            return f"{text} =~ {apl_string(value)} or {text} endswith {apl_string(chr(92) + str(value))}"
        return f"{text} =~ {apl_string(value)}"

    def queries(self, dataset: str) -> list:
        out = []
        for time_clause, conditions in self.observations.items():
            where = conditions[0] if len(conditions) == 1 else ' or '.join(f"({c})" for c in conditions)
            out.append(f"['{dataset}'] | where {time_clause} | where {where}")
        return out


def translate_pattern(pattern: Pattern, translator, options) -> list:
    """Build the APL query for ``pattern``.

    ``options.dataset`` names the Axiom dataset (default ``ocsf``, the name
    Axiom recommends for OCSF data).
    """
    dataset = str((options or {}).get('dataset') or 'ocsf').strip()
    if not DATASET_PATTERN.match(dataset):
        raise ValueError(f"Invalid Axiom dataset name: {dataset!r}")
    return AplQueryBuilder(pattern, translator, options).queries(dataset)
