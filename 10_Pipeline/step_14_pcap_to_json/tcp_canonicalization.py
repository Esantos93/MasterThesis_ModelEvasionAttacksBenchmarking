from __future__ import annotations

import hashlib
import ipaddress
from bisect import bisect_left
from collections import Counter, defaultdict
from typing import Any


TCP_SEQUENCE_MODULUS = 1 << 32
TCP_SYN_FLAG = 0x02
TCP_FIN_FLAG = 0x01
TCP_ACK_FLAG = 0x10
TCP_RST_FLAG = 0x04


# This helper creates compact deterministic identifiers from stable TCP coordinates.
def stable_id(prefix: str, *parts: Any) -> str:
    source = "|".join(str(part) for part in parts)
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


# This helper sorts IP endpoints numerically so connection direction does not depend on packet capture order.
def endpoint_sort_key(endpoint: tuple[str, int]) -> tuple[int, bytes, int]:
    ip_text, port = endpoint
    try:
        address = ipaddress.ip_address(ip_text)
        return address.version, address.packed, port
    except ValueError:
        return 0, ip_text.encode("utf-8"), port


# This function returns the normalized bidirectional key and deterministic direction for one TCP packet.
def connection_coordinates(record: dict[str, Any]) -> tuple[tuple[Any, ...], str, tuple[str, int], tuple[str, int]]:
    source = (str(record.get("src_ip", "")), int(record.get("src_port") or 0))
    destination = (str(record.get("dst_ip", "")), int(record.get("dst_port") or 0))
    endpoints = sorted([source, destination], key=endpoint_sort_key)
    endpoint_a, endpoint_b = endpoints[0], endpoints[1]
    direction = "a_to_b" if source == endpoint_a else "b_to_a"
    return (6, *endpoint_a, *endpoint_b), direction, endpoint_a, endpoint_b


# This function unwraps a 32-bit TCP number to the closest coordinate around the previous observation.
def unwrap_tcp_number(value: int, checkpoint: int | None) -> int:
    value &= 0xFFFFFFFF
    if checkpoint is None:
        return value
    cycle = checkpoint // TCP_SEQUENCE_MODULUS
    candidates = [
        value + ((cycle - 1) * TCP_SEQUENCE_MODULUS),
        value + (cycle * TCP_SEQUENCE_MODULUS),
        value + ((cycle + 1) * TCP_SEQUENCE_MODULUS),
    ]
    return min(candidates, key=lambda candidate: (abs(candidate - checkpoint), candidate))


# This helper returns the payload bytes represented by one stream sub-interval.
def segment_bytes(segment: dict[str, Any], start: int, end: int) -> bytes:
    offset_start = start - int(segment["start"])
    offset_end = end - int(segment["start"])
    return segment["payload"][offset_start:offset_end]


# This helper checks whether two TCP payload segments overlap in stream coordinates.
def overlapping_interval(first: dict[str, Any], second: dict[str, Any]) -> tuple[int, int] | None:
    start = max(int(first["start"]), int(second["start"]))
    end = min(int(first["end"]), int(second["end"]))
    return (start, end) if start < end else None


# This function finds a deterministic multi-segment cover for one interval without using a complete single segment.
def alternative_cover(
    start: int,
    end: int,
    expected: bytes,
    segments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates = [
        segment
        for segment in segments
        if int(segment["end"]) > start
        and int(segment["start"]) < end
        and not (int(segment["start"]) <= start and int(segment["end"]) >= end)
    ]
    cursor = start
    components = []
    used_packet_ids = set()
    while cursor < end:
        covering = [
            segment
            for segment in candidates
            if int(segment["start"]) <= cursor < int(segment["end"])
        ]
        covering.sort(key=lambda segment: (-int(segment["end"]), int(segment["reduced_packet_index"])))
        selected = None
        for segment in covering:
            component_end = min(end, int(segment["end"]))
            expected_slice = expected[cursor - start : component_end - start]
            if segment_bytes(segment, cursor, component_end) == expected_slice:
                selected = segment
                break
        if selected is None:
            return []
        component_end = min(end, int(selected["end"]))
        components.append({"segment": selected, "start": cursor, "end": component_end})
        used_packet_ids.add(str(selected["packet_id"]))
        cursor = component_end
    return components if len(used_packet_ids) >= 2 else []


# This helper updates the ordered public classification fields after internal classification tags change.
def refresh_segment_classification(segment: dict[str, Any]) -> None:
    priority = [
        "overlap_contradictory",
        "exact_retransmission",
        "alternative_segmentation",
        "partial_retransmission",
        "overlap_consistent",
        "independent_segment",
    ]
    tags = segment["classification_tags"]
    if len(tags) > 1:
        tags.discard("independent_segment")
    segment["classifications"] = [tag for tag in priority if tag in tags]
    segment["classification"] = segment["classifications"][0]


# This function classifies overlapping payload segments with a stream-coordinate sweep instead of all-pairs comparison.
def classify_segments(segments: list[dict[str, Any]]) -> None:
    active: list[dict[str, Any]] = []
    ordered_segments = sorted(segments, key=lambda item: (item["start"], item["end"], item["reduced_packet_index"]))
    for segment in ordered_segments:
        tags = set()
        active = [previous for previous in active if previous["end"] > segment["start"]]
        for previous in active:
            overlap = overlapping_interval(segment, previous)
            if overlap is None:
                continue
            start, end = overlap
            if segment_bytes(segment, start, end) != segment_bytes(previous, start, end):
                tags.add("overlap_contradictory")
                continue
            same_interval = segment["start"] == previous["start"] and segment["end"] == previous["end"]
            containment = (
                segment["start"] <= previous["start"] and segment["end"] >= previous["end"]
            ) or (
                previous["start"] <= segment["start"] and previous["end"] >= segment["end"]
            )
            if same_interval:
                tags.add("exact_retransmission")
            elif containment:
                tags.add("partial_retransmission")
            else:
                tags.add("overlap_consistent")
        if not tags:
            tags.add("independent_segment")
        segment["classification_tags"] = tags
        refresh_segment_classification(segment)
        active.append(segment)


# This function creates the smallest non-overlapping stream intervals and records all byte variants per interval.
def build_atomic_regions(segments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    boundaries = sorted({coordinate for segment in segments for coordinate in [segment["start"], segment["end"]]})
    ordered_segments = sorted(segments, key=lambda item: (item["start"], item["end"], item["reduced_packet_index"]))
    active: list[dict[str, Any]] = []
    segment_index = 0
    atoms = []
    for start, end in zip(boundaries, boundaries[1:]):
        while segment_index < len(ordered_segments) and ordered_segments[segment_index]["start"] <= start:
            active.append(ordered_segments[segment_index])
            segment_index += 1
        active = [segment for segment in active if segment["end"] > start]
        covering = [segment for segment in active if segment["end"] >= end]
        if not covering:
            continue
        variants: dict[bytes, list[dict[str, Any]]] = defaultdict(list)
        for segment in covering:
            variants[segment_bytes(segment, start, end)].append(segment)
        representative = min(covering, key=lambda segment: int(segment["reduced_packet_index"]))
        atoms.append(
            {
                "start": start,
                "end": end,
                "payload": segment_bytes(representative, start, end),
                "status": "consistent" if len(variants) == 1 else "conflict",
                "covering": covering,
                "variants": variants,
            }
        )
    return atoms


# This function merges atoms only when they form a proven complete-vs-segmented equivalent representation.
def merge_alternative_segmentation_atoms(
    atoms: list[dict[str, Any]],
    segments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merge_intervals = []
    unique_intervals = {}
    for segment in segments:
        payload_digest = hashlib.sha256(segment["payload"]).digest()
        unique_intervals.setdefault((int(segment["start"]), int(segment["end"]), payload_digest), segment)
    atom_starts = [int(atom["start"]) for atom in atoms]
    for segment in unique_intervals.values():
        start, end = int(segment["start"]), int(segment["end"])
        atom_index = bisect_left(atom_starts, start)
        relevant_atoms = []
        while atom_index < len(atoms) and atoms[atom_index]["end"] <= end:
            relevant_atoms.append(atoms[atom_index])
            atom_index += 1
        local_segments = list(
            {
                id(candidate): candidate
                for atom in relevant_atoms
                for candidate in atom["covering"]
                if candidate is not segment
            }.values()
        )
        if alternative_cover(start, end, segment["payload"], local_segments):
            merge_intervals.append((start, end))
    merge_intervals.sort(key=lambda interval: (interval[0], -(interval[1] - interval[0])))

    merged = []
    atom_index = 0
    while atom_index < len(atoms):
        atom = atoms[atom_index]
        candidate_intervals = [
            interval
            for interval in merge_intervals
            if interval[0] == atom["start"] and interval[1] > atom["end"]
        ]
        selected_interval = candidate_intervals[0] if candidate_intervals else None
        if selected_interval is None:
            merged.append(atom)
            atom_index += 1
            continue
        end = selected_interval[1]
        selected_atoms = []
        while atom_index < len(atoms) and atoms[atom_index]["start"] < end:
            selected_atoms.append(atoms[atom_index])
            atom_index += 1
        if selected_atoms[-1]["end"] != end or any(atom_part["status"] != "consistent" for atom_part in selected_atoms):
            merged.extend(selected_atoms)
            continue
        merged.append(
            {
                "start": selected_atoms[0]["start"],
                "end": end,
                "payload": b"".join(atom_part["payload"] for atom_part in selected_atoms),
                "status": "consistent",
                "covering": list({id(segment): segment for atom_part in selected_atoms for segment in atom_part["covering"]}.values()),
                "variants": {b"".join(atom_part["payload"] for atom_part in selected_atoms): []},
            }
        )
    return merged


# This helper creates one compact physical slice that maps packet payload bytes onto a canonical region.
def build_physical_slice(region_id: str, region: dict[str, Any], segment: dict[str, Any]) -> dict[str, Any]:
    stream_start = max(int(region["start"]), int(segment["start"]))
    stream_end = min(int(region["end"]), int(segment["end"]))
    representation_id = stable_id("tcp_repr", region_id, segment["packet_id"], stream_start, stream_end)
    return {
        "physical_representation_id": representation_id,
        "canonical_region_id": region_id,
        "packet_id": segment["packet_id"],
        "stream_start": stream_start,
        "stream_end": stream_end,
        "region_offset_start_bytes": stream_start - int(region["start"]),
        "region_offset_end_bytes": stream_end - int(region["start"]),
        "packet_payload_offset_start_bytes": stream_start - int(segment["start"]),
        "packet_payload_offset_end_bytes": stream_end - int(segment["start"]),
        "covers_entire_region": stream_start == region["start"] and stream_end == region["end"],
    }


# This helper converts a deterministic segment cover into references to the physical slices used by that cover.
def representation_set_components(
    cover: list[dict[str, Any]],
    slices_by_packet: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    components = []
    for component in cover:
        packet_id = str(component["segment"]["packet_id"])
        physical_slice = slices_by_packet[packet_id]
        components.append(
            {
                "physical_representation_id": physical_slice["physical_representation_id"],
                "stream_start": component["start"],
                "stream_end": component["end"],
            }
        )
    return components


# This function canonicalizes one directional stream into regions, aliases, representation sets, and conflicts.
def canonicalize_stream(
    stream_id: str,
    connection_id: str,
    direction: str,
    segments: list[dict[str, Any]],
) -> dict[str, Any]:
    classify_segments(segments)
    regions = merge_alternative_segmentation_atoms(build_atomic_regions(segments), segments)
    canonical_regions = []
    physical_slices = []
    representation_sets = []
    conflicts = []
    ordered_segments = sorted(segments, key=lambda item: (item["start"], item["end"], item["reduced_packet_index"]))
    active_segments: list[dict[str, Any]] = []
    segment_index = 0

    for region in regions:
        region_id = stable_id("tcp_region", stream_id, region["start"], region["end"])
        while segment_index < len(ordered_segments) and ordered_segments[segment_index]["start"] < region["end"]:
            active_segments.append(ordered_segments[segment_index])
            segment_index += 1
        active_segments = [segment for segment in active_segments if segment["end"] > region["start"]]
        intersecting = list(active_segments)
        slices = [build_physical_slice(region_id, region, segment) for segment in intersecting]
        slices_by_packet = {str(item["packet_id"]): item for item in slices}
        physical_slices.extend(slices)

        set_ids = []
        for item in slices:
            if not item["covers_entire_region"]:
                continue
            set_id = stable_id("tcp_repr_set", region_id, item["physical_representation_id"])
            set_ids.append(set_id)
            representation_sets.append(
                {
                    "representation_set_id": set_id,
                    "canonical_region_id": region_id,
                    "representation_type": "complete_segment",
                    "components": [
                        {
                            "physical_representation_id": item["physical_representation_id"],
                            "stream_start": region["start"],
                            "stream_end": region["end"],
                        }
                    ],
                }
            )

        cover = (
            alternative_cover(int(region["start"]), int(region["end"]), region["payload"], intersecting)
            if region["status"] == "consistent"
            else []
        )
        if cover:
            components = representation_set_components(cover, slices_by_packet)
            set_id = stable_id("tcp_repr_set", region_id, *(component["physical_representation_id"] for component in components))
            set_ids.append(set_id)
            representation_sets.append(
                {
                    "representation_set_id": set_id,
                    "canonical_region_id": region_id,
                    "representation_type": "segment_combination",
                    "components": components,
                }
            )
            for component in cover:
                component["segment"]["classification_tags"].add("alternative_segmentation")
            for complete_segment in intersecting:
                if complete_segment["start"] <= region["start"] and complete_segment["end"] >= region["end"]:
                    complete_segment["classification_tags"].add("alternative_segmentation")

        representative = min(intersecting, key=lambda segment: int(segment["reduced_packet_index"]))
        canonical_regions.append(
            {
                "canonical_region_id": region_id,
                "tcp_connection_id": connection_id,
                "tcp_stream_id": stream_id,
                "direction": direction,
                "stream_start": region["start"],
                "stream_end": region["end"],
                "length": region["end"] - region["start"],
                "representative_packet_id": representative["packet_id"],
                "payload_hex": region["payload"].hex(),
                "physical_representations": set_ids,
                "physical_alias_ids": [item["physical_representation_id"] for item in slices],
                "byte_consistency_status": region["status"],
            }
        )

        if region["status"] == "conflict":
            variants = []
            for payload, variant_segments in sorted(region["variants"].items(), key=lambda item: item[0]):
                variants.append(
                    {
                        "payload_sha256": hashlib.sha256(payload).hexdigest(),
                        "packet_ids": sorted(str(segment["packet_id"]) for segment in variant_segments),
                    }
                )
            conflicts.append(
                {
                    "conflict_id": stable_id("tcp_conflict", stream_id, region["start"], region["end"]),
                    "tcp_connection_id": connection_id,
                    "tcp_stream_id": stream_id,
                    "direction": direction,
                    "stream_start": region["start"],
                    "stream_end": region["end"],
                    "packet_ids": sorted(str(segment["packet_id"]) for segment in intersecting),
                    "variants": variants,
                }
            )

    for segment in segments:
        refresh_segment_classification(segment)

    return {
        "regions": canonical_regions,
        "physical_slices": physical_slices,
        "representation_sets": representation_sets,
        "conflicts": conflicts,
    }


# This function validates the canonical contract before Step 14 writes an artifact consumed by downstream steps.
def validate_canonical_contract(records: list[dict[str, Any]], result: dict[str, Any]) -> None:
    regions = result["canonical_tcp_regions"]
    region_ids = [str(region["canonical_region_id"]) for region in regions]
    if len(region_ids) != len(set(region_ids)):
        raise ValueError("TCP canonicalization produced duplicate canonical_region_id values.")

    representation_ids = [
        str(item["physical_representation_id"])
        for item in result["tcp_physical_representations"]
    ]
    if len(representation_ids) != len(set(representation_ids)):
        raise ValueError("TCP canonicalization produced duplicate physical_representation_id values.")

    regions_by_stream: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for region in regions:
        regions_by_stream[str(region["tcp_stream_id"])].append(region)
    for stream_id, stream_regions in regions_by_stream.items():
        ordered = sorted(stream_regions, key=lambda item: (item["stream_start"], item["stream_end"]))
        for previous, current in zip(ordered, ordered[1:]):
            if int(previous["stream_end"]) > int(current["stream_start"]):
                raise ValueError(f"Canonical TCP regions overlap inside stream {stream_id}.")

    known_region_ids = set(region_ids)
    for record in records:
        if record.get("transport_protocol") != "TCP":
            continue
        if not all(record.get(field) for field in ["tcp_connection_id", "tcp_direction", "tcp_stream_id"]):
            raise ValueError(f"TCP packet lacks connection or direction identity: {record.get('packet_id')}")
        payload_length = int(record.get("payload_length_bytes") or 0)
        mappings = sorted(
            record.get("canonical_region_mappings", []),
            key=lambda item: item["packet_payload_offset_start_bytes"],
        )
        if payload_length == 0:
            if mappings:
                raise ValueError(f"Payload-free TCP packet has canonical payload mappings: {record.get('packet_id')}")
            continue
        cursor = 0
        for mapping in mappings:
            if str(mapping["canonical_region_id"]) not in known_region_ids:
                raise ValueError(f"Packet mapping references an unknown canonical region: {mapping}")
            start = int(mapping["packet_payload_offset_start_bytes"])
            end = int(mapping["packet_payload_offset_end_bytes"])
            if start != cursor or end <= start:
                raise ValueError(f"Canonical mappings do not tile packet payload {record.get('packet_id')} exactly.")
            cursor = end
        if cursor != payload_length:
            raise ValueError(f"Canonical mappings do not cover all payload bytes for {record.get('packet_id')}.")


# This function enriches physical packet records and returns all top-level TCP canonicalization tables.
def canonicalize_tcp_records(records: list[dict[str, Any]], oversized_frame_threshold_bytes: int = 1514) -> dict[str, Any]:
    connection_records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    connection_details: dict[str, dict[str, Any]] = {}
    stream_records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    session_states: dict[tuple[Any, ...], dict[str, Any]] = {}

    for record in records:
        frame_length = int(record.get("packet_length_bytes") or 0)
        record["frame_oversized"] = frame_length > oversized_frame_threshold_bytes
        record["frame_size_class"] = "oversized_gso_like" if record["frame_oversized"] else "standard"
        if record.get("transport_protocol") != "TCP":
            continue
        key, direction, endpoint_a, endpoint_b = connection_coordinates(record)
        flags = int(record.get("tcp_flags") or 0)
        sequence = int(record.get("tcp_seq") or 0)
        initial_syn = bool(flags & TCP_SYN_FLAG) and not bool(flags & TCP_ACK_FLAG)
        state = session_states.get(key)
        previous_syn = state["initial_syn_by_direction"].get(direction) if state else None
        starts_new_instance = state is None or (
            initial_syn and (state["closed"] or previous_syn is None or previous_syn != sequence)
        )
        if starts_new_instance:
            occurrence = 1 if state is None else int(state["occurrence"]) + 1
            state = {
                "occurrence": occurrence,
                "connection_id": stable_id("tcp_conn", *key, "instance", occurrence),
                "initial_syn_by_direction": {},
                "fin_directions": set(),
                "closed": False,
                "packet_count": 0,
            }
            session_states[key] = state
        if initial_syn:
            state["initial_syn_by_direction"].setdefault(direction, sequence)
        connection_id = str(state["connection_id"])
        stream_id = f"{connection_id}_{direction}"
        record["tcp_connection_id"] = connection_id
        record["tcp_direction"] = direction
        record["tcp_stream_id"] = stream_id
        connection_records[connection_id].append(record)
        stream_records[stream_id].append(record)
        state["packet_count"] += 1
        connection_details.setdefault(
            connection_id,
            {
                "tcp_connection_id": connection_id,
                "protocol": "TCP",
                "protocol_number": 6,
                "connection_instance": state["occurrence"],
                "normalized_connection_key": {
                    "protocol_number": 6,
                    "ip_a": endpoint_a[0],
                    "port_a": endpoint_a[1],
                    "ip_b": endpoint_b[0],
                    "port_b": endpoint_b[1],
                },
                "endpoint_a": {"ip": endpoint_a[0], "port": endpoint_a[1]},
                "endpoint_b": {"ip": endpoint_b[0], "port": endpoint_b[1]},
            },
        )
        if flags & TCP_FIN_FLAG:
            state["fin_directions"].add(direction)
            state["closed"] = len(state["fin_directions"]) == 2
        if flags & TCP_RST_FLAG:
            state["closed"] = True

    stream_origins = {}
    stream_segments: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for stream_id, packet_records in stream_records.items():
        checkpoint = None
        for record in packet_records:
            sequence = int(record.get("tcp_seq") or 0)
            unwrapped = unwrap_tcp_number(sequence, checkpoint)
            checkpoint = unwrapped
            record["tcp_seq_unwrapped"] = unwrapped
        origin = min(int(record["tcp_seq_unwrapped"]) for record in packet_records)
        stream_origins[stream_id] = origin
        for record in packet_records:
            flags = int(record.get("tcp_flags") or 0)
            syn = 1 if flags & TCP_SYN_FLAG else 0
            fin = 1 if flags & TCP_FIN_FLAG else 0
            payload = bytes.fromhex(str(record.get("payload_hex", "")))
            sequence_start = int(record["tcp_seq_unwrapped"]) - origin
            payload_start = sequence_start + syn
            payload_end = payload_start + len(payload)
            record.update(
                {
                    "tcp_syn_sequence_consumption": syn,
                    "tcp_fin_sequence_consumption": fin,
                    "tcp_sequence_space_start": sequence_start,
                    "tcp_sequence_space_end": sequence_start + syn + len(payload) + fin,
                    "tcp_payload_stream_start": payload_start if payload else None,
                    "tcp_payload_stream_end": payload_end if payload else None,
                    "canonical_region_ids": [],
                    "canonical_region_mappings": [],
                }
            )
            if payload:
                stream_segments[stream_id].append(
                    {
                        "packet_id": str(record["packet_id"]),
                        "reduced_packet_index": int(record["reduced_packet_index"]),
                        "record": record,
                        "start": payload_start,
                        "end": payload_end,
                        "payload": payload,
                    }
                )

    for connection_id, packet_records in connection_records.items():
        ack_checkpoints: dict[str, int | None] = {"a_to_b": None, "b_to_a": None}
        for record in packet_records:
            direction = str(record["tcp_direction"])
            ack = int(record.get("tcp_ack") or 0)
            opposite_direction = "b_to_a" if direction == "a_to_b" else "a_to_b"
            opposite_stream_id = f"{connection_id}_{opposite_direction}"
            has_ack = bool(int(record.get("tcp_flags") or 0) & TCP_ACK_FLAG)
            if has_ack:
                checkpoint = ack_checkpoints[direction]
                if checkpoint is None:
                    checkpoint = stream_origins.get(opposite_stream_id)
                unwrapped_ack = unwrap_tcp_number(ack, checkpoint)
                ack_checkpoints[direction] = unwrapped_ack
                record["tcp_ack_unwrapped"] = unwrapped_ack
                record["tcp_ack_stream_offset"] = (
                    unwrapped_ack - stream_origins[opposite_stream_id]
                    if opposite_stream_id in stream_origins
                    else None
                )
            else:
                record["tcp_ack_unwrapped"] = None
                record["tcp_ack_stream_offset"] = None

    canonical_regions = []
    physical_representations = []
    representation_sets = []
    conflicts = []
    stream_table = []
    classification_counts: Counter[str] = Counter()
    classification_tag_counts: Counter[str] = Counter()

    for stream_id, packet_records in sorted(stream_records.items()):
        first = packet_records[0]
        connection_id = str(first["tcp_connection_id"])
        direction = str(first["tcp_direction"])
        segments = stream_segments.get(stream_id, [])
        result = canonicalize_stream(stream_id, connection_id, direction, segments) if segments else {
            "regions": [], "physical_slices": [], "representation_sets": [], "conflicts": []
        }
        canonical_regions.extend(result["regions"])
        physical_representations.extend(result["physical_slices"])
        representation_sets.extend(result["representation_sets"])
        conflicts.extend(result["conflicts"])

        mappings_by_packet: dict[str, list[dict[str, Any]]] = defaultdict(list)
        region_ids_by_packet: dict[str, set[str]] = defaultdict(set)
        for physical_slice in result["physical_slices"]:
            packet_id = str(physical_slice["packet_id"])
            region_id = str(physical_slice["canonical_region_id"])
            region_ids_by_packet[packet_id].add(region_id)
            mappings_by_packet[packet_id].append(
                {
                    "canonical_region_id": region_id,
                    "physical_representation_id": physical_slice["physical_representation_id"],
                    "stream_start": physical_slice["stream_start"],
                    "stream_end": physical_slice["stream_end"],
                    "packet_payload_offset_start_bytes": physical_slice["packet_payload_offset_start_bytes"],
                    "packet_payload_offset_end_bytes": physical_slice["packet_payload_offset_end_bytes"],
                }
            )
        for segment in segments:
            record = segment["record"]
            record["tcp_segment_classification"] = segment["classification"]
            record["tcp_segment_classifications"] = segment["classifications"]
            record["canonical_region_ids"] = sorted(region_ids_by_packet[str(record["packet_id"])])
            record["canonical_region_mappings"] = sorted(
                mappings_by_packet[str(record["packet_id"])], key=lambda item: (item["stream_start"], item["stream_end"])
            )
            classification_counts[segment["classification"]] += 1
            classification_tag_counts.update(segment["classifications"])

        source = connection_details[connection_id]["endpoint_a"] if direction == "a_to_b" else connection_details[connection_id]["endpoint_b"]
        destination = connection_details[connection_id]["endpoint_b"] if direction == "a_to_b" else connection_details[connection_id]["endpoint_a"]
        stream_table.append(
            {
                "tcp_stream_id": stream_id,
                "tcp_connection_id": connection_id,
                "direction": direction,
                "source_endpoint": source,
                "destination_endpoint": destination,
                "sequence_origin_unwrapped": stream_origins[stream_id],
                "packet_count": len(packet_records),
                "payload_segment_count": len(segments),
                "payload_byte_span": max((segment["end"] for segment in segments), default=0),
                "canonical_region_ids": [region["canonical_region_id"] for region in result["regions"]],
                "conflict_count": len(result["conflicts"]),
            }
        )

    connection_table = []
    for connection_id, details in sorted(connection_details.items()):
        packet_records = connection_records[connection_id]
        connection_table.append(
            {
                **details,
                "packet_count": len(packet_records),
                "first_packet_id": packet_records[0]["packet_id"],
                "last_packet_id": packet_records[-1]["packet_id"],
                "tcp_stream_ids": sorted({str(record["tcp_stream_id"]) for record in packet_records}),
            }
        )

    result = {
        "tcp_connections": connection_table,
        "tcp_streams": stream_table,
        "canonical_tcp_regions": canonical_regions,
        "tcp_physical_representations": physical_representations,
        "tcp_representation_sets": representation_sets,
        "tcp_canonicalization_conflicts": conflicts,
        "summary": {
            "tcp_packet_count": sum(len(items) for items in connection_records.values()),
            "tcp_connection_count": len(connection_table),
            "tcp_stream_count": len(stream_table),
            "tcp_payload_segment_count": sum(len(items) for items in stream_segments.values()),
            "canonical_region_count": len(canonical_regions),
            "consistent_region_count": sum(region["byte_consistency_status"] == "consistent" for region in canonical_regions),
            "conflicting_region_count": sum(region["byte_consistency_status"] == "conflict" for region in canonical_regions),
            "conflict_count": len(conflicts),
            "physical_representation_count": len(physical_representations),
            "representation_set_count": len(representation_sets),
            "segment_classification_counts": dict(sorted(classification_counts.items())),
            "segment_classification_tag_counts": dict(sorted(classification_tag_counts.items())),
            "oversized_frame_threshold_bytes": oversized_frame_threshold_bytes,
            "oversized_frame_count": sum(bool(record.get("frame_oversized")) for record in records),
            "maximum_frame_length_bytes": max((int(record.get("packet_length_bytes") or 0) for record in records), default=0),
            "oversized_frames_are_complete_captured_frames": True,
            "oversized_frame_interpretation": "Observed oversized frames are inventoried as GSO-like/offload artifacts; Step 14 does not classify them as truncated or infer missing bytes.",
        },
    }
    validate_canonical_contract(records, result)
    return result
