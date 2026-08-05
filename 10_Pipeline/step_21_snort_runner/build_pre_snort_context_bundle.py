from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


PIPELINE_ROOT = Path(__file__).resolve().parents[1]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from common.ids_context import (
    IDS_CONTEXT_MAPPING_POLICY,
    PRE_SNORT_CONTEXT_BUNDLE_SCHEMA_VERSION,
    detector_identity,
    validate_pre_snort_context_bundle,
)
from common.io_utils import write_json


CATALOG_SCHEMA_VERSION = "ids_detector_catalog_v1"
DEFAULT_CATALOG_PATH = Path(__file__).with_name("ids_detector_catalog_v1.json")
RULE_ACTIONS = {"alert", "block", "drop", "log", "pass", "reject", "sdrop"}
SNORT_VERSION_PATTERN = re.compile(r"Snort\+\+\s+([0-9][0-9A-Za-z.+_-]*)")
OPTION_PATTERN_TEMPLATE = r"(?:^|;)\s*{name}\s*:\s*([^;]+)"


#This function reads a source artifact used to build the canonical PRE Snort bundle.
def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as input_file:
        return json.load(input_file)


#This function hashes every consumed source artifact for reproducible bundle provenance.
def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


#This function fails before bundle construction when a required source artifact is missing.
def require_file(path: Path, description: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise FileNotFoundError(f"Missing {description}: {resolved}")
    if not resolved.is_file():
        raise ValueError(f"{description} must be a regular file: {resolved}")
    return resolved


#This function resolves a metadata-recorded artifact against the actual PRE directory.
def resolve_recorded_artifact(pre_snort_dir: Path, recorded_path: Any, description: str) -> Path:
    if not isinstance(recorded_path, str) or not recorded_path.strip():
        raise ValueError(f"Step 21 metadata does not record {description}.")
    candidate = Path(recorded_path).expanduser()
    if candidate.is_file():
        return candidate.resolve()
    local_candidate = pre_snort_dir / candidate.name
    return require_file(local_candidate, description)


#This function rejects POST or ambiguous Snort metadata so only PRE evidence can reach the model.
def ensure_pre_metadata(metadata: dict[str, Any], pre_snort_dir: Path) -> None:
    if metadata.get("traffic_version") != "pre":
        raise ValueError("Only Step 21 PRE metadata can be used to build the context bundle.")
    traffic_scope = str(metadata.get("traffic_scope", ""))
    if not traffic_scope.startswith("pre"):
        raise ValueError(f"Step 21 traffic_scope must identify PRE traffic; found {traffic_scope!r}.")
    if "post" in {part.lower() for part in pre_snort_dir.parts}:
        raise ValueError(f"The supplied Snort directory is a POST directory: {pre_snort_dir}")
    if metadata.get("exit_code") != 0:
        raise ValueError("Step 21 PRE execution did not complete successfully.")


#This function extracts the exact Snort version from the canonical PRE execution log.
def parse_snort_version(stdout_path: Path) -> str:
    match = SNORT_VERSION_PATTERN.search(stdout_path.read_text(encoding="utf-8", errors="replace"))
    if not match:
        raise ValueError(f"Could not extract the Snort version from: {stdout_path}")
    return match.group(1)


#This function builds the Step 14 packet identity index used to anchor PRE alerts unambiguously.
def packet_trace_by_reduced_index(packet_json: dict[str, Any]) -> dict[int, dict[str, Any]]:
    if packet_json.get("metadata", {}).get("schema_version") != "packet_json_v4":
        raise ValueError("The PRE context bundle requires Step 14 packet_json_v4.")
    traffic = packet_json.get("traffic")
    if not isinstance(traffic, list):
        raise ValueError("Step 14 packet JSON must contain a traffic list.")
    lookup: dict[int, dict[str, Any]] = {}
    packet_ids: set[str] = set()
    for packet in traffic:
        if not isinstance(packet, dict):
            raise ValueError("Every Step 14 traffic item must be an object.")
        reduced_index = packet.get("reduced_packet_index")
        packet_id = packet.get("packet_id")
        if isinstance(reduced_index, bool) or not isinstance(reduced_index, int) or reduced_index <= 0:
            raise ValueError("Every Step 14 packet must have a positive reduced_packet_index.")
        if not isinstance(packet_id, str) or not packet_id:
            raise ValueError("Every Step 14 packet must have a non-empty packet_id.")
        if reduced_index in lookup:
            raise ValueError(f"Ambiguous reduced_packet_index in Step 14 traffic: {reduced_index}")
        if packet_id in packet_ids:
            raise ValueError(f"Duplicate packet_id in Step 14 traffic: {packet_id!r}")
        lookup[reduced_index] = packet
        packet_ids.add(packet_id)
    return lookup


#This function counts unquoted rule parentheses so multiline declarations can be reconstructed safely.
def _parenthesis_delta(text: str) -> int:
    delta = 0
    quoted = False
    escaped = False
    for character in text:
        if escaped:
            escaped = False
            continue
        if character == "\\" and quoted:
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
        elif not quoted and character == "(":
            delta += 1
        elif not quoted and character == ")":
            delta -= 1
    return delta


#This function extracts complete Snort rule declarations from one text source.
def extract_rule_declarations(text: str) -> list[str]:
    declarations: list[str] = []
    current: list[str] = []
    depth = 0
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        first_word = stripped.split(None, 1)[0].lower()
        if not current:
            if first_word not in RULE_ACTIONS or "(" not in stripped:
                continue
            current = [stripped]
            depth = _parenthesis_delta(stripped)
        else:
            current.append(stripped)
            depth += _parenthesis_delta(stripped)
        if current and depth <= 0:
            declarations.append(" ".join(current))
            current = []
            depth = 0
    if current:
        raise ValueError("Unterminated Snort rule declaration encountered.")
    return declarations


#This function reads one scalar Snort rule option without reimplementing detector logic.
def rule_option(declaration: str, name: str) -> str | None:
    options_start = declaration.find("(")
    options_end = declaration.rfind(")")
    if options_start < 0 or options_end <= options_start:
        return None
    options = declaration[options_start + 1 : options_end]
    match = re.search(OPTION_PATTERN_TEMPLATE.format(name=re.escape(name)), options, flags=re.IGNORECASE)
    return match.group(1).strip() if match else None


#This function derives the gid/sid/rev identity from a textual rule declaration.
def rule_identity(declaration: str) -> tuple[int, int, int] | None:
    sid_text = rule_option(declaration, "sid")
    rev_text = rule_option(declaration, "rev")
    if sid_text is None or rev_text is None:
        return None
    gid_text = rule_option(declaration, "gid")
    try:
        return int(gid_text) if gid_text is not None else 1, int(sid_text), int(rev_text)
    except ValueError as error:
        raise ValueError(f"Invalid gid/sid/rev in rule declaration: {declaration}") from error


#This function expands configured rule sources into a deterministic ordered file list.
def rule_source_files(sources: Iterable[Path]) -> list[Path]:
    files: set[Path] = set()
    for source in sources:
        resolved = source.expanduser().resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Rule source does not exist: {resolved}")
        if resolved.is_file():
            files.add(resolved)
        elif resolved.is_dir():
            files.update(path.resolve() for path in resolved.rglob("*.rules") if path.is_file())
        else:
            raise ValueError(f"Rule source must be a file or directory: {resolved}")
    return sorted(files, key=lambda path: str(path))


#This function indexes detector declarations and rejects contradictory identities.
def build_rule_index(files: list[Path]) -> tuple[dict[tuple[int, int, int], tuple[str, Path]], set[Path]]:
    index: dict[tuple[int, int, int], tuple[str, Path]] = {}
    duplicate_sources: set[Path] = set()
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for declaration in extract_rule_declarations(text):
            identity = rule_identity(declaration)
            if identity is None:
                continue
            previous = index.get(identity)
            if previous is not None and previous[0] != declaration:
                raise ValueError(
                    f"Contradictory rule declarations for gid/sid/rev={identity}: "
                    f"{previous[1]} and {path}"
                )
            if previous is not None:
                duplicate_sources.add(path)
            else:
                index[identity] = (declaration, path)
    return index, duplicate_sources


#This function loads curated SO and built-in semantics from the versioned auditable catalog.
def load_catalog(path: Path) -> dict[tuple[int, int, int], dict[str, Any]]:
    catalog = read_json(require_file(path, "IDS detector catalog"))
    if not isinstance(catalog, dict) or catalog.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise ValueError(f"Detector catalog must use schema_version={CATALOG_SCHEMA_VERSION!r}.")
    records = catalog.get("records")
    if not isinstance(records, list):
        raise ValueError("Detector catalog must contain a records list.")
    lookup: dict[tuple[int, int, int], dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Detector catalog records must be objects.")
        identity = detector_identity(record)
        if identity in lookup and lookup[identity] != record:
            raise ValueError(f"Contradictory detector catalog records for {identity}.")
        lookup[identity] = record
    return lookup


#This function obtains one consistent detector message across all occurrences of a signature.
def normalized_message(alerts: list[dict[str, Any]], identity: tuple[int, int, int]) -> str:
    messages = {str(alert.get("message", "")).strip() for alert in alerts if detector_identity(alert) == identity}
    messages.discard("")
    if len(messages) != 1:
        raise ValueError(f"Detector {identity} has missing or contradictory PRE alert messages: {sorted(messages)}")
    return next(iter(messages))


#This function builds one source-specific detector definition for a signature observed in PRE.
def build_detector_definition(
    *,
    identity: tuple[int, int, int],
    message: str,
    rule_index: dict[tuple[int, int, int], tuple[str, Path]],
    catalog: dict[tuple[int, int, int], dict[str, Any]],
) -> tuple[dict[str, Any], Path | None]:
    gid, sid, rev = identity
    common = {"gid": gid, "sid": sid, "rev": rev, "message": message}
    if gid == 1:
        if identity not in rule_index:
            raise ValueError(f"No text rule declaration found for active detector {identity}.")
        declaration, source_path = rule_index[identity]
        return {**common, "detector_source": "ruleset_text", "rule_declaration": declaration}, source_path
    if gid == 3:
        curated = catalog.get(identity)
        if identity in rule_index:
            declaration, source_path = rule_index[identity]
        elif curated is not None and isinstance(curated.get("so_rule_stub"), str):
            declaration = curated["so_rule_stub"].strip()
            source_path = None
            if not declaration:
                raise ValueError(f"Catalog SO rule stub is empty for active detector {identity}.")
        else:
            raise ValueError(f"No SO rule stub found for active detector {identity}.")
        definition = {**common, "detector_source": "ruleset_so", "so_rule_stub": declaration}
        if curated is not None:
            if curated.get("detector_source") != "ruleset_so":
                raise ValueError(f"Catalog source mismatch for SO detector {identity}.")
            if "security_context" in curated:
                definition["security_context"] = curated["security_context"]
        return definition, source_path
    curated = catalog.get(identity)
    if curated is None:
        raise ValueError(f"No curated built-in detector definition found for active detector {identity}.")
    if curated.get("detector_source") != "builtin_decoder_or_inspector":
        raise ValueError(f"Catalog source mismatch for built-in detector {identity}.")
    return {
        **common,
        "detector_source": "builtin_decoder_or_inspector",
        "inspector": curated["inspector"],
        "semantic_description": curated["semantic_description"],
    }, None


#This function retains only compact non-payload event evidence from a raw PRE alert.
def bounded_event_data(alert: dict[str, Any]) -> dict[str, Any]:
    keys = [
        "action",
        "class",
        "proto",
        "src_addr",
        "src_port",
        "dst_addr",
        "dst_port",
        "pkt_num",
        "pkt_len",
    ]
    return {key: alert[key] for key in keys if key in alert and alert[key] is not None}


#This function registers one consumed artifact and its digest exactly once.
def add_source_artifact(artifacts: dict[str, str], path: Path) -> None:
    resolved = require_file(path, "source artifact")
    artifacts[str(resolved)] = sha256_file(resolved)


#This function derives a stable identifier from the ordered ruleset files and contents.
def combined_ruleset_identifier(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(set(paths), key=lambda item: str(item)):
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(path).encode("ascii"))
        digest.update(b"\n")
    return f"active_pre_detector_sources_sha256:{digest.hexdigest()}"


#This function joins PRE alerts, packet identities, rules, and execution metadata into the shared bundle.
def build_pre_snort_context_bundle(
    *,
    pre_snort_dir: Path,
    packet_json_path: Path,
    output_path: Path,
    detector_catalog_path: Path = DEFAULT_CATALOG_PATH,
    additional_rule_sources: list[Path] | None = None,
    input_pcap_override: Path | None = None,
    ruleset_override: Path | None = None,
    rules_policy_override: Path | None = None,
) -> dict[str, Any]:
    pre_dir = pre_snort_dir.expanduser().resolve()
    if not pre_dir.is_dir():
        raise FileNotFoundError(f"Step 21 PRE Snort directory does not exist: {pre_dir}")
    metadata_path = require_file(pre_dir / "execution_metadata.json", "Step 21 PRE execution metadata")
    execution_metadata = read_json(metadata_path)
    if not isinstance(execution_metadata, dict):
        raise ValueError("Step 21 execution metadata must be a JSON object.")
    ensure_pre_metadata(execution_metadata, pre_dir)

    converted_alert_path = resolve_recorded_artifact(
        pre_dir,
        (execution_metadata.get("artifacts") or {}).get("converted_alert_json"),
        "Step 21 converted PRE alert JSON",
    )
    stdout_path = resolve_recorded_artifact(
        pre_dir,
        (execution_metadata.get("artifacts") or {}).get("stdout"),
        "Step 21 PRE stdout log",
    )
    input_pcap_path = require_file(
        input_pcap_override or Path(str(execution_metadata.get("input_pcap", ""))),
        "Step 21 PRE input PCAP",
    )
    packet_path = require_file(packet_json_path, "Step 14 packet JSON")
    catalog_path = require_file(detector_catalog_path, "IDS detector catalog")

    packet_json = read_json(packet_path)
    if not isinstance(packet_json, dict):
        raise ValueError("Step 14 packet JSON must be a JSON object.")
    packet_lookup = packet_trace_by_reduced_index(packet_json)
    recorded_packet_pcap = packet_json.get("metadata", {}).get("source_selected_pcap")
    if isinstance(recorded_packet_pcap, str) and Path(recorded_packet_pcap).exists():
        if Path(recorded_packet_pcap).resolve() != input_pcap_path:
            raise ValueError("Step 14 packet JSON and Step 21 metadata reference different PRE PCAP files.")

    raw_alerts = read_json(converted_alert_path)
    if not isinstance(raw_alerts, list):
        raise ValueError("Step 21 converted PRE alerts must be a JSON array.")
    alerts: list[dict[str, Any]] = []
    for alert_index, raw_alert in enumerate(raw_alerts, start=1):
        if not isinstance(raw_alert, dict):
            raise ValueError(f"Step 21 PRE alert {alert_index} is not an object.")
        try:
            gid = int(raw_alert["gid"])
            sid = int(raw_alert["sid"])
            rev = int(raw_alert["rev"])
            pkt_num = int(raw_alert["pkt_num"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"Step 21 PRE alert {alert_index} lacks integer gid/sid/rev/pkt_num.") from error
        packet = packet_lookup.get(pkt_num)
        if packet is None:
            raise ValueError(
                f"Step 21 PRE alert {alert_index} references pkt_num={pkt_num}, "
                "which does not resolve to a Step 14 reduced_packet_index."
            )
        message = str(raw_alert.get("msg", "")).strip()
        if not message:
            raise ValueError(f"Step 21 PRE alert {alert_index} has no message.")
        normalized_alert = {
            "alert_id": f"pre_alert_{alert_index:06d}",
            "gid": gid,
            "sid": sid,
            "rev": rev,
            "message": message,
            "anchor_packet_ids": [str(packet["packet_id"])],
            "event_data": bounded_event_data(raw_alert),
        }
        timestamp = raw_alert.get("timestamp")
        if isinstance(timestamp, str) and timestamp.strip():
            normalized_alert["timestamp"] = timestamp
        alerts.append(normalized_alert)

    active_identities = sorted({detector_identity(alert) for alert in alerts})
    ruleset_path = require_file(
        ruleset_override or Path(str(execution_metadata.get("ruleset_path", ""))),
        "configured Snort ruleset",
    )
    rules_policy_value = str(execution_metadata.get("rules_policy_path", "")).strip()
    rules_policy_path = (
        require_file(rules_policy_override, "configured Snort rules policy")
        if rules_policy_override is not None
        else require_file(Path(rules_policy_value), "configured Snort rules policy")
        if rules_policy_value
        else None
    )
    plugin_path_value = str(execution_metadata.get("plugin_path", "")).strip()
    automatic_sources = [ruleset_path.parent]
    if plugin_path_value and Path(plugin_path_value).exists():
        automatic_sources.append(Path(plugin_path_value))
    all_rule_sources = automatic_sources + list(additional_rule_sources or [])
    rule_files = rule_source_files(all_rule_sources)
    rule_index, _duplicate_sources = build_rule_index(rule_files)
    catalog = load_catalog(catalog_path)

    detector_definitions: list[dict[str, Any]] = []
    matched_rule_sources: list[Path] = []
    for identity in active_identities:
        definition, source_path = build_detector_definition(
            identity=identity,
            message=normalized_message(alerts, identity),
            rule_index=rule_index,
            catalog=catalog,
        )
        detector_definitions.append(definition)
        if source_path is not None:
            matched_rule_sources.append(source_path)

    source_artifact_hashes: dict[str, str] = {}
    base_artifacts = [metadata_path, converted_alert_path, stdout_path, input_pcap_path, packet_path, catalog_path, ruleset_path]
    if rules_policy_path is not None:
        base_artifacts.append(rules_policy_path)
    for artifact in base_artifacts + matched_rule_sources:
        add_source_artifact(source_artifact_hashes, artifact)

    ruleset_identity_paths = [ruleset_path, *matched_rule_sources]
    if rules_policy_path is not None:
        ruleset_identity_paths.append(rules_policy_path)
    snaplen = execution_metadata.get("snaplen")
    if isinstance(snaplen, bool) or not isinstance(snaplen, int) or snaplen <= 0:
        raise ValueError("Step 21 PRE metadata must record a positive snaplen.")
    builtin_rules_enabled = execution_metadata.get("enable_builtin_rules")
    if not isinstance(builtin_rules_enabled, bool):
        raise ValueError("Step 21 PRE metadata must record enable_builtin_rules as a boolean.")
    detector_policy = str(execution_metadata.get("detector_policy_label", "")).strip()
    if not detector_policy:
        raise ValueError("Step 21 PRE metadata must record detector_policy_label.")

    bundle = {
        "schema_version": PRE_SNORT_CONTEXT_BUNDLE_SCHEMA_VERSION,
        "metadata": {
            "snort_version": parse_snort_version(stdout_path),
            "detector_policy": detector_policy,
            "snaplen": snaplen,
            "builtin_rules_enabled": builtin_rules_enabled,
            "ruleset_identifier": combined_ruleset_identifier(ruleset_identity_paths),
            "source_artifacts": sorted(source_artifact_hashes),
            "source_hashes": {key: source_artifact_hashes[key] for key in sorted(source_artifact_hashes)},
            "mapping_policy": IDS_CONTEXT_MAPPING_POLICY,
        },
        "detector_definitions": detector_definitions,
        "alerts": alerts,
    }
    validate_pre_snort_context_bundle(bundle)
    write_json(output_path, bundle)
    return bundle


#This function resolves the canonical Step 21 PRE directory below a baseline experiment root.
def resolve_default_pre_dir(baseline_root: Path) -> Path:
    matches = sorted(path for path in (baseline_root / "11_snort_raw").glob("*/pre") if path.is_dir())
    if len(matches) != 1:
        raise ValueError(
            "Could not resolve one canonical Step 21 PRE directory under "
            f"{baseline_root / '11_snort_raw'}; found {len(matches)}. Pass --pre-snort-dir explicitly."
        )
    return matches[0]


#This function parses explicit baseline inputs without hardcoding experiment names.
def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build pre_snort_context_bundle_v1 from canonical PRE evidence.")
    parser.add_argument("--baseline-experiment-root", help="Baseline experiment root used to derive default paths.")
    parser.add_argument("--pre-snort-dir", help="Canonical Step 21 PRE output directory.")
    parser.add_argument("--packet-json", help="Step 14 selected_packet_records.json path.")
    parser.add_argument("--output", required=True, help="Output pre_snort_context_bundle_v1.json path.")
    parser.add_argument(
        "--detector-catalog",
        default=str(DEFAULT_CATALOG_PATH),
        help="Versioned SO/built-in detector catalog.",
    )
    parser.add_argument("--input-pcap", help="Local relocation of the PRE PCAP recorded by Step 21.")
    parser.add_argument("--ruleset-path", help="Local relocation of the configured Snort ruleset entry file.")
    parser.add_argument("--rules-policy-path", help="Local relocation of the configured Snort rules policy.")
    parser.add_argument(
        "--rules-source",
        action="append",
        default=[],
        help="Additional Snort rule file or directory. May be supplied more than once.",
    )
    return parser.parse_args()


#This function builds, validates, and writes the reusable PRE Snort context bundle.
def main() -> None:
    args = parse_cli_args()
    baseline_root = Path(args.baseline_experiment_root).expanduser() if args.baseline_experiment_root else None
    if args.pre_snort_dir:
        pre_snort_dir = Path(args.pre_snort_dir)
    elif baseline_root is not None:
        pre_snort_dir = resolve_default_pre_dir(baseline_root)
    else:
        raise ValueError("Pass --pre-snort-dir or --baseline-experiment-root.")
    if args.packet_json:
        packet_json = Path(args.packet_json)
    elif baseline_root is not None:
        packet_json = baseline_root / "04_packet_json" / "selected_packet_records.json"
    else:
        raise ValueError("Pass --packet-json or --baseline-experiment-root.")

    bundle = build_pre_snort_context_bundle(
        pre_snort_dir=pre_snort_dir,
        packet_json_path=packet_json,
        output_path=Path(args.output).expanduser(),
        detector_catalog_path=Path(args.detector_catalog).expanduser(),
        additional_rule_sources=[Path(value) for value in args.rules_source],
        input_pcap_override=Path(args.input_pcap).expanduser() if args.input_pcap else None,
        ruleset_override=Path(args.ruleset_path).expanduser() if args.ruleset_path else None,
        rules_policy_override=Path(args.rules_policy_path).expanduser() if args.rules_policy_path else None,
    )
    print(f"PRE Snort context bundle: {Path(args.output).expanduser()}")
    print(f"Alerts: {len(bundle['alerts'])}")
    print(f"Detector definitions: {len(bundle['detector_definitions'])}")
    print(f"Snort version: {bundle['metadata']['snort_version']}")
    print(f"Detector policy: {bundle['metadata']['detector_policy']}")


if __name__ == "__main__":
    main()
