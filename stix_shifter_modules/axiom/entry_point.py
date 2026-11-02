from stix_shifter_utils.utils.base_entry_point import BaseEntryPoint
from stix_shifter_utils.utils.module_discovery import dialect_list

# Field layouts the module knows. ``ocsf`` follows Axiom's OCSF 1.9 schema
# (nested objects flattened to dotted columns such as ``src_endpoint.ip``);
# ``windows`` follows raw Windows Security and Sysmon event fields
# (``DestinationIp``, ``Image``, ``CommandLine``...).
DEFAULT_SCHEMA = 'ocsf'


def active_schemas(options):
    """The field layouts to translate for.

    stix-shifter's own ``options.dialects`` wins. Otherwise the module option
    ``field_schema`` picks one or more layouts (comma separated, or ``all``).
    The default is ``ocsf`` only, so a pattern runs one query, not one per
    layout.
    """
    options = options or {}
    if options.get('dialects'):
        return list(options['dialects'])
    value = str(options.get('field_schema') or DEFAULT_SCHEMA).strip().lower()
    if value == 'all':
        return None
    return [part.strip() for part in value.split(',') if part.strip()] or [DEFAULT_SCHEMA]


class EntryPoint(BaseEntryPoint):

    # python main.py translate axiom query '{}' "[ipv4-addr:value = '198.51.100.66']" \
    #     '{"dataset": "huntbase-security", "field_schema": "windows"}'

    def __init__(self, connection={}, configuration={}, options={}):
        super().__init__(connection, configuration, options)
        self.set_async(False)

        if connection:
            self.setup_transmission_basic(connection, configuration)

        dialects = dialect_list('axiom', {})
        wanted = active_schemas(options)
        default = (wanted or [DEFAULT_SCHEMA])[0]
        if default not in dialects:
            default = DEFAULT_SCHEMA
        for dialect in dialects:
            self.add_dialect(dialect, default=(dialect == default),
                             default_include=(wanted is None or dialect in wanted))
