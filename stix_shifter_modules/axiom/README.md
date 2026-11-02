# Axiom

Connector for [Axiom](https://axiom.co) datasets, queried with the Axiom Processing Language (APL) through
`POST /v1/datasets/_apl?format=tabular`. Huntbase fork only; not in upstream stix-shifter.

## Connection

| Field | Where | Notes |
|-------|-------|-------|
| `host` | connection | `api.axiom.co` (default). Queries use the API host in every region; only ingest needs the regional edge domain. |
| `port` | connection | 443 |
| `org_id` | connection | Optional. Sent as `X-AXIOM-ORG-ID`; only needed with a personal access token. |
| `api_key` | configuration.auth | Axiom API token with query permission on the dataset. Sent as `Authorization: Bearer`. |
| `dataset` | connection.options | Dataset to search. Default `ocsf`, the name Axiom recommends for OCSF data. |
| `field_schema` | connection.options | Field layout of the dataset: `ocsf` (default), `windows`, a comma-separated list, or `all`. Each layout produces its own query. |
| `field_map` | connection.options | Optional JSON that adds dataset fields to STIX properties, for datasets with their own field names: `{"ipv4-addr": {"fields": {"value": ["client_ip"]}}}`. |

stix-shifter's own `options.dialects` and `options.mapping` also work (`dialects` overrides `field_schema`).

## Field layouts (dialects)

* `ocsf`: the [Axiom OCSF schema](https://axiom.co/docs/use-cases/ocsf) (OCSF 1.9, nested objects flattened to
  dotted columns such as `src_endpoint.ip`, `process.cmd_line`, `file.hashes`).
* `windows`: raw Windows Security and Sysmon event fields (`SourceIp`, `DestinationIp`, `QueryName`, `Image`,
  `CommandLine`, `Hashes`, `User`, `TargetUserName`, ...).

## Translation

```
[ipv4-addr:value = '198.51.100.66'] START t'2026-11-02T12:00:00Z' STOP t'2026-11-02T12:30:00Z'
```

with `{"dataset": "huntbase-security", "field_schema": "windows"}` becomes

```
['huntbase-security']
| where _time between (datetime(2026-11-02T12:00:00.000Z) .. datetime(2026-11-02T12:30:00.000Z))
| where (tostring(column_ifexists('SourceIp', '')) =~ '198.51.100.66')
     or (tostring(column_ifexists('DestinationIp', '')) =~ '198.51.100.66')
     or (tostring(column_ifexists('IpAddress', '')) =~ '198.51.100.66')
```

* Every field is read with `column_ifexists()`: Axiom rejects a query that names a missing column, and its
  datasets only have the columns their events filled.
* String equality is case-insensitive (`=~`). `IN` uses `in~`, `LIKE` and `MATCHES` use `matches regex`,
  `ISSUBSET` uses `ipv4_is_in_range()`, `>`/`<` use `toreal()` (or `todatetime()` for timestamps).
* Hash fields (`Hashes`, `file.hashes`) match with `contains`. Path and account fields (`Image`, `User`, ...)
  also match a bare name (`process:name = 'svc.exe'` matches `C:\...\svc.exe`; `user-account:user_id =
  'jsmith'` matches `DOMAIN\jsmith`).
* Without a START/STOP qualifier the window is the last `time_range` minutes. Axiom rejects an `or` of time
  ranges, so each distinct window gets its own query; observations that share a window share one query.

## Transmission

* Ping: `GET /v2/datasets/<dataset>` (checks the token and access to the dataset).
* Query: synchronous; the search id is the APL query.
* Results: the query plus `| sort by _time desc | take <offset + length>`, with `startTime`/`endTime` taken from
  the query's window. Axiom has no offset, so the first `offset` rows are dropped. Rows are returned as Axiom
  sends them (dotted column names, nulls dropped).
* Errors: 400 `invalid_query` (Axiom's message is kept), 401 and 403 `authentication_fail`,
  404 `invalid_parameter`, 429 and 430 (organisation query limit) `too_many_requests`.

## Results to STIX

`ocsf_to_stix_map.json` and `windows_to_stix_map.json` are combined. Before mapping, dotted OCSF columns are
nested again, and OCSF `hashes` lists and Sysmon `Hashes` strings are split into one STIX hash per algorithm.

## Tests

```
pytest stix_shifter_modules/axiom/tests
```
