# Header Editability Policies

This folder contains the versioned Step 15 header editability policies used to
decide which physical Ethernet/IPv4/TCP header fields may be exposed to the
LLM.

Step 14 still emits the complete `packet_json_v4` factual reference. Step 15
loads one policy through:

```text
pipeline.header_editability_policy_path
```

The policy classifies structured header fields into:

| Classification | Meaning |
| --- | --- |
| `llm_editable_headers_region` | May be exposed to the LLM as a bounded physical-header edit. |
| `pipeline_controlled_field` | May change only as a deterministic consequence of materialization, translation, or checksum/length recomputation. |
| `immutable_field` | Must not be modified by the LLM. |

Every policy in this folder uses:

```text
default_classification = immutable_field
```

So a field that is not matched by a rule is treated as immutable.

## Policy Index

| File | `policy_id` | Intended use | Editable header fields |
| --- | --- | --- | --- |
| `header_v1.json` | `conservative_header_editability_v1` | Conservative baseline/header-only policy used by the standard header-only configs. | 3 |
| `header_expanded_v1.json` | `expanded_header_editability_v1` | Extended/aggressive header-modification policy for the parked Valid vs Invalid Traffic experiment candidate. | 17 |

Known active config references:

| Config family | Policy |
| --- | --- |
| `config_LLM_baseline_Llama31_8B.json` and other baseline model configs | `header_v1.json` |
| `config_LLM_flow_based_headers.json` | `header_v1.json` |
| `config_LLM_expanded_header_editability.json` | `header_expanded_v1.json` historical/experimental expanded-header config; not part of the current Main Baseline matrix unless explicitly reopened. |

## `header_v1.json`

Policy id:

```text
conservative_header_editability_v1
```

Purpose:

Conservative first header policy. It exposes only bounded packet-scoped fields
that do not redefine flow identity, TCP byte ownership, packet length,
checksums, parsing boundaries, or TCP state translation.

### Editable Fields

| Field | Range | Pipeline recalculates |
| --- | --- | --- |
| `ipv4.tos` | `0..255` | `ipv4.checksum` |
| `ipv4.ttl` | `1..255` | `ipv4.checksum` |
| `tcp.window` | `0..65535` | `tcp.checksum` |

### Pipeline-Controlled Fields

| Field | Reason |
| --- | --- |
| `ipv4.total_length` | Must match final serialized IPv4 length. |
| `ipv4.checksum` | Recomputed after IPv4 header edits. |
| `tcp.sequence_number` | Stream coordinate translated by the pipeline. |
| `tcp.acknowledgement_number` | Cross-direction TCP state translated by the pipeline. |
| `tcp.data_offset_reserved_ns` | Defines TCP header/options boundary. |
| `tcp.checksum` | Recomputed over final TCP header and payload. |

### Immutable Fields

| Field group | Fields |
| --- | --- |
| Ethernet identity/parser selection | `ethernet.destination_mac`, `ethernet.source_mac`, `ethernet.outer_ether_type`, `ethernet.ether_type` |
| IPv4 identity/parser selection | `ipv4.version`, `ipv4.ihl_words`, `ipv4.protocol`, `ipv4.source_address`, `ipv4.destination_address` |
| IPv4 fragmentation/ID | `ipv4.identification`, `ipv4.flags_fragment_offset`, `ipv4.flags.reserved`, `ipv4.flags.dont_fragment`, `ipv4.flags.more_fragments`, `ipv4.fragment_offset_units` |
| TCP identity | `tcp.source_port`, `tcp.destination_port` |
| TCP flags/state | `tcp.flags`, `tcp.flags.ns`, `tcp.flags.cwr`, `tcp.flags.ece`, `tcp.flags.urg`, `tcp.flags.ack`, `tcp.flags.psh`, `tcp.flags.rst`, `tcp.flags.syn`, `tcp.flags.fin` |
| TCP urgent data | `tcp.urgent_pointer` |

## `header_expanded_v1.json`

Policy id:

```text
expanded_header_editability_v1
```

Purpose:

Extended/aggressive header-only policy for the parked `Valid Traffic vs Invalid
Traffic` experiment candidate described in `20_Notes/Experiments Diary.md`. It
deliberately exposes a larger IPv4/TCP header surface than the conservative
Baseline to test whether broader header editability changes Snort evasion
behavior and whether downstream validation rejects invalid traffic. Lengths,
checksums, parser-selection fields, flow identity, TCP sequence/acknowledgement
state, TCP ACK, and TCP NS remain non-editable.

### Editable Fields

| Field | Range | Notes |
| --- | --- | --- |
| `ipv4.tos` | `0..255` | Same as conservative policy. |
| `ipv4.identification` | `0..65535` | Experimental; active Step 14 contract rejects fragmented IPv4 packets. |
| `ipv4.ttl` | `1..255` | Same as conservative policy. |
| `tcp.window` | `0..65535` | Same as conservative policy. |
| `ipv4.flags_fragment_offset` | `0..65535` | Experimental combined flags/fragment-offset word. |
| `ipv4.flags.reserved` | `0..1` | Experimental fragmentation flag bit. |
| `ipv4.flags.dont_fragment` | `0..1` | Experimental fragmentation flag bit. |
| `ipv4.flags.more_fragments` | `0..1` | Experimental fragmentation flag bit. |
| `ipv4.fragment_offset_units` | `0..8191` | Experimental 13-bit fragment offset. |
| `tcp.flags.cwr` | `0..1` | Experimental TCP control bit. |
| `tcp.flags.ece` | `0..1` | Experimental TCP control bit. |
| `tcp.flags.urg` | `0..1` | Experimental TCP control bit. |
| `tcp.flags.psh` | `0..1` | Experimental TCP control bit. |
| `tcp.flags.rst` | `0..1` | Experimental TCP control bit. |
| `tcp.flags.syn` | `0..1` | Experimental TCP control bit. |
| `tcp.flags.fin` | `0..1` | Experimental TCP control bit. |
| `tcp.urgent_pointer` | `0..65535` | Experimental; meaningful mainly with `tcp.flags.urg`. |

### Pipeline-Controlled Fields

Same as `header_v1.json`:

| Field | Reason |
| --- | --- |
| `ipv4.total_length` | Must match final serialized IPv4 length. |
| `ipv4.checksum` | Recomputed after IPv4 header edits. |
| `tcp.sequence_number` | Stream coordinate translated by the pipeline. |
| `tcp.acknowledgement_number` | Cross-direction TCP state translated by the pipeline. |
| `tcp.data_offset_reserved_ns` | Defines TCP header/options boundary. |
| `tcp.checksum` | Recomputed over final TCP header and payload. |

### Immutable Fields

| Field group | Fields |
| --- | --- |
| Ethernet identity/parser selection | `ethernet.destination_mac`, `ethernet.source_mac`, `ethernet.outer_ether_type`, `ethernet.ether_type` |
| IPv4 identity/parser selection | `ipv4.version`, `ipv4.ihl_words`, `ipv4.protocol`, `ipv4.source_address`, `ipv4.destination_address` |
| TCP identity | `tcp.source_port`, `tcp.destination_port` |
| TCP aggregate/remaining flags | `tcp.flags`, `tcp.flags.ns`, `tcp.flags.ack` |

## Reading Guidance

Use this README as a quick overview. Use the JSON policy files as the
authoritative source for:

- exact `rule_id` values;
- `allowed_operations`;
- full constraints;
- source references;
- detailed rationale.

When adding a new policy:

1. Keep `schema_version = header_editability_policy_v1` unless the parser
   contract changes.
2. Set a unique `policy_id`.
3. Keep `default_classification = immutable_field` unless the methodology
   explicitly changes.
4. Add the new file to the Policy Index above.
5. Update the relevant experiment config's
   `pipeline.header_editability_policy_path`.
