from __future__ import annotations

import ctypes
import json
import os
from collections import Counter
from typing import Any


MIB = 1024 * 1024


def _linux_memory_snapshot() -> dict[str, float]:
    status_values: dict[str, int] = {}
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as status_file:
            for line in status_file:
                key, separator, value = line.partition(":")
                if separator and key in {"VmRSS", "VmHWM"}:
                    status_values[key] = int(value.strip().split()[0]) * 1024
    except (FileNotFoundError, OSError, ValueError):
        pass

    available_bytes = None
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as meminfo_file:
            for line in meminfo_file:
                if line.startswith("MemAvailable:"):
                    available_bytes = int(line.split()[1]) * 1024
                    break
    except (FileNotFoundError, OSError, ValueError):
        pass

    result: dict[str, float] = {}
    if "VmRSS" in status_values:
        result["rss_mib"] = round(status_values["VmRSS"] / MIB, 1)
    if "VmHWM" in status_values:
        result["peak_rss_mib"] = round(status_values["VmHWM"] / MIB, 1)
    if available_bytes is not None:
        result["available_memory_mib"] = round(available_bytes / MIB, 1)
    return result


def _windows_memory_snapshot() -> dict[str, float]:
    if os.name != "nt":
        return {}

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    result: dict[str, float] = {}
    try:
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        process = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(
            process,
            ctypes.byref(counters),
            counters.cb,
        ):
            result["rss_mib"] = round(counters.WorkingSetSize / MIB, 1)
            result["peak_rss_mib"] = round(counters.PeakWorkingSetSize / MIB, 1)
    except (AttributeError, OSError):
        pass

    try:
        status = MemoryStatus()
        status.dwLength = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            result["available_memory_mib"] = round(status.ullAvailPhys / MIB, 1)
    except (AttributeError, OSError):
        pass
    return result


def process_memory_snapshot() -> dict[str, float]:
    snapshot = _linux_memory_snapshot()
    if snapshot:
        return snapshot
    return _windows_memory_snapshot()


def memory_snapshot_text() -> str:
    snapshot = process_memory_snapshot()
    return ", ".join(f"{key}={value}" for key, value in snapshot.items())


def summarize_token_plan(token_plan: dict[str, Any]) -> dict[str, Any]:
    breakdown = token_plan.get("breakdown", {})
    bounded_breakdown = {
        key: value
        for key, value in breakdown.items()
        if key not in {"worst_case_output", "payload_replacement_limits"}
    }
    payload_limits = breakdown.get("payload_replacement_limits", [])
    if isinstance(payload_limits, list):
        bounded_breakdown["payload_replacement_limit_count"] = len(payload_limits)
        effective_limits = [
            int(limit.get("effective_limit_bytes") or 0)
            for limit in payload_limits
            if isinstance(limit, dict)
        ]
        bounded_breakdown["maximum_payload_replacement_bytes"] = max(
            effective_limits,
            default=0,
        )
    return {
        key: value
        for key, value in token_plan.items()
        if key != "breakdown"
    } | {"breakdown": bounded_breakdown}


class PlanningDiagnostics:
    def __init__(self) -> None:
        self.unit_count = 0
        self.header_packet_atom_count = 0
        self.payload_entry_count = 0
        self.payload_editable_byte_count = 0
        self.input_token_total = 0
        self.output_token_total = 0
        self.total_planned_token_total = 0
        self.maximum_total_planned_tokens = 0
        self.alias_context_chars_total = 0
        self.alias_context_chars_max = 0
        self.alias_count_total = 0
        self.alias_count_max = 0
        self.target_presence_counts: Counter[str] = Counter()
        self.unit_type_counts: Counter[str] = Counter()
        self.payload_mode_entry_counts: Counter[str] = Counter()
        self.payload_mode_byte_counts: Counter[str] = Counter()
        self.payload_window_length_counts: Counter[int] = Counter()
        self.parent_group_unit_counts: Counter[str] = Counter()

    def observe_unit(self, unit: dict[str, Any]) -> None:
        self.unit_count += 1
        parent_group_id = str(unit["parent_group_id"])
        self.parent_group_unit_counts[parent_group_id] += 1
        self.unit_type_counts[str(unit["unit_type"])] += 1

        presence = unit.get("editable_target_presence", {})
        has_headers = bool(presence.get("editable_headers_present"))
        has_payload = bool(presence.get("editable_payload_present"))
        presence_key = (
            "mixed"
            if has_headers and has_payload
            else "header_only"
            if has_headers
            else "payload_only"
        )
        self.target_presence_counts[presence_key] += 1
        self.header_packet_atom_count += len(unit.get("physical_packets", []))

        for entry in unit.get("canonical_payload_regions", []):
            if not isinstance(entry, dict):
                continue
            self.payload_entry_count += 1
            mode = str(entry.get("semantic_segmentation", {}).get("mode", "unknown"))
            editable_regions = entry.get("editable_regions", [])
            entry_bytes = sum(
                int(region.get("length_bytes") or 0)
                for region in editable_regions
                if isinstance(region, dict)
            )
            self.payload_editable_byte_count += entry_bytes
            self.payload_mode_entry_counts[mode] += 1
            self.payload_mode_byte_counts[mode] += entry_bytes
            if mode == "adaptive_byte_window":
                self.payload_window_length_counts[entry_bytes] += 1

            aliases = entry.get("physical_aliases", [])
            alias_count = len(aliases) if isinstance(aliases, list) else 0
            alias_chars = len(
                json.dumps(
                    aliases if isinstance(aliases, list) else [],
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
            self.alias_count_total += alias_count
            self.alias_count_max = max(self.alias_count_max, alias_count)
            self.alias_context_chars_total += alias_chars
            self.alias_context_chars_max = max(self.alias_context_chars_max, alias_chars)

        token_plan = unit.get("token_plan", {})
        estimated_input_tokens = int(token_plan.get("estimated_input_tokens") or 0)
        planned_output_tokens = int(token_plan.get("planned_output_tokens") or 0)
        total_planned_tokens = int(token_plan.get("total_planned_tokens") or 0)
        self.input_token_total += estimated_input_tokens
        self.output_token_total += planned_output_tokens
        self.total_planned_token_total += total_planned_tokens
        self.maximum_total_planned_tokens = max(
            self.maximum_total_planned_tokens,
            total_planned_tokens,
        )

    def as_dict(self) -> dict[str, Any]:
        payload_window_count = sum(self.payload_window_length_counts.values())
        payload_window_bytes = sum(
            length * count for length, count in self.payload_window_length_counts.items()
        )
        top_parent_groups = sorted(
            self.parent_group_unit_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )[:20]
        return {
            "modification_unit_count": self.unit_count,
            "unit_target_presence_counts": dict(sorted(self.target_presence_counts.items())),
            "unit_type_counts": dict(sorted(self.unit_type_counts.items())),
            "header_packet_atom_count": self.header_packet_atom_count,
            "payload_entry_count": self.payload_entry_count,
            "payload_editable_byte_count": self.payload_editable_byte_count,
            "payload_mode_entry_counts": dict(sorted(self.payload_mode_entry_counts.items())),
            "payload_mode_byte_counts": dict(sorted(self.payload_mode_byte_counts.items())),
            "adaptive_window_statistics": {
                "count": payload_window_count,
                "editable_bytes": payload_window_bytes,
                "length_bytes_min": min(self.payload_window_length_counts, default=None),
                "length_bytes_max": max(self.payload_window_length_counts, default=None),
                "length_bytes_mean": (
                    round(payload_window_bytes / payload_window_count, 4)
                    if payload_window_count
                    else None
                ),
                "length_distribution": {
                    str(length): count
                    for length, count in sorted(self.payload_window_length_counts.items())
                },
            },
            "physical_alias_context": {
                "alias_count_total": self.alias_count_total,
                "alias_count_max_per_entry": self.alias_count_max,
                "serialized_chars_total": self.alias_context_chars_total,
                "serialized_chars_max_per_entry": self.alias_context_chars_max,
            },
            "token_totals": {
                "estimated_input_tokens": self.input_token_total,
                "planned_output_tokens": self.output_token_total,
                "total_planned_tokens": self.total_planned_token_total,
                "maximum_total_planned_tokens": self.maximum_total_planned_tokens,
                "mean_estimated_input_tokens": (
                    round(self.input_token_total / self.unit_count, 4)
                    if self.unit_count
                    else None
                ),
                "mean_planned_output_tokens": (
                    round(self.output_token_total / self.unit_count, 4)
                    if self.unit_count
                    else None
                ),
            },
            "top_parent_groups_by_modification_unit_count": [
                {
                    "parent_group_id": parent_group_id,
                    "modification_unit_count": count,
                }
                for parent_group_id, count in top_parent_groups
            ],
            "memory_at_report": process_memory_snapshot(),
        }
