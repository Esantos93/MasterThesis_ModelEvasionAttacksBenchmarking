from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import run_llm_batch
import summarize_llm_runtime


#This function reads JSON using the shared Step 17 helper.
def read_json(path: Path) -> Any:
    return run_llm_batch.read_json(path)


#This function resolves the prompt file recorded in metadata, with local prompt-dir fallbacks.
def resolve_prompt_path(metadata: dict[str, Any], prompt_dirs: list[Path]) -> Path | None:
    prompt_file = metadata.get("prompt_file")
    if isinstance(prompt_file, str) and prompt_file:
        recorded_path = Path(prompt_file)
        if recorded_path.exists():
            return recorded_path
        for prompt_dir in prompt_dirs:
            fallback_path = prompt_dir / recorded_path.name
            if fallback_path.exists():
                return fallback_path

    prompt_unit_id = metadata.get("prompt_unit_id")
    if isinstance(prompt_unit_id, str) and prompt_unit_id:
        for prompt_dir in prompt_dirs:
            fallback_path = prompt_dir / f"{prompt_unit_id}.prompt.json"
            if fallback_path.exists():
                return fallback_path
    return None


#This function removes failure artifacts and metadata paths superseded by an accepted reparse.
def remove_superseded_failure_artifacts(
    *,
    failure_path: Path,
    rejected_path: Path,
    output_paths: dict[str, Any],
) -> list[Path]:
    output_paths.pop("failure", None)
    output_paths.pop("rejected_json", None)

    removed_paths = []
    for stale_path in [failure_path, rejected_path]:
        if stale_path.exists():
            stale_path.unlink()
            removed_paths.append(stale_path)
    return removed_paths


#This function reparses one raw output and optionally rewrites parsed/metadata/failure artifacts.
def reparse_one_raw_output(
    *,
    raw_path: Path,
    run_dir: Path,
    prompt_dirs: list[Path],
    write: bool,
) -> dict[str, Any]:
    output_stem = raw_path.name.removesuffix(".raw.txt")
    metadata_path = run_dir / "metadata" / f"{output_stem}.metadata.json"
    parsed_path = run_dir / "parsed" / f"{output_stem}.parsed.json"
    failure_path = run_dir / "failures" / f"{output_stem}.failure.json"
    rejected_path = run_dir / "failures" / f"{output_stem}.rejected.json"

    if not metadata_path.exists():
        return {"raw_file": str(raw_path), "status": "skipped", "reason": "missing_metadata"}

    metadata = read_json(metadata_path)
    prompt_path = resolve_prompt_path(metadata, prompt_dirs)
    if prompt_path is None:
        return {"raw_file": str(raw_path), "status": "skipped", "reason": "missing_prompt_file"}

    prompt_package = run_llm_batch.validate_prompt_package(read_json(prompt_path), prompt_path)
    raw_text = raw_path.read_text(encoding="utf-8")
    original_status = metadata.get("status")
    original_failure_reason = metadata.get("failure_reason")

    try:
        parsed_output = run_llm_batch.parse_model_json(raw_text)
        validation_result = run_llm_batch.validate_patch_output(parsed_output, prompt_package)
        if validation_result["accepted"]:
            new_status = "accepted"
            new_failure_reason = None
            output_paths = dict(metadata.get("output_paths") or {})
            output_paths["raw"] = str(raw_path)
            output_paths["parsed"] = str(parsed_path)
            output_paths["metadata"] = str(metadata_path)
            if write:
                run_llm_batch.write_json(parsed_path, parsed_output)
                remove_superseded_failure_artifacts(
                    failure_path=failure_path,
                    rejected_path=rejected_path,
                    output_paths=output_paths,
                )
        else:
            new_status = "failed"
            new_failure_reason = validation_result["reason"]
            output_paths = dict(metadata.get("output_paths") or {})
            output_paths["raw"] = str(raw_path)
            output_paths["metadata"] = str(metadata_path)
            output_paths["failure"] = str(failure_path)
            output_paths["rejected_json"] = str(rejected_path)
            if write:
                failure_report = {
                    "failure_reason": new_failure_reason,
                    "parent_group_id": metadata.get("parent_group_id"),
                    "prompt_unit_id": metadata.get("prompt_unit_id"),
                    "prompt_file": str(prompt_path),
                    "model_name": metadata.get("model_name"),
                    "validation_result": validation_result,
                }
                run_llm_batch.write_json(failure_path, failure_report)
                run_llm_batch.write_json(rejected_path, parsed_output)
    except Exception as error:
        parsed_output = None
        validation_result = None
        new_status = "failed"
        new_failure_reason = type(error).__name__
        output_paths = dict(metadata.get("output_paths") or {})
        output_paths["raw"] = str(raw_path)
        output_paths["metadata"] = str(metadata_path)
        output_paths["failure"] = str(failure_path)
        if write:
            failure_report = {
                "failure_reason": new_failure_reason,
                "failure_message": str(error),
                "parent_group_id": metadata.get("parent_group_id"),
                "prompt_unit_id": metadata.get("prompt_unit_id"),
                "prompt_file": str(prompt_path),
                "model_name": metadata.get("model_name"),
            }
            run_llm_batch.write_json(failure_path, failure_report)

    if write:
        metadata["status"] = new_status
        metadata["failure_reason"] = new_failure_reason
        metadata["output_paths"] = output_paths
        metadata["validation_result"] = validation_result
        metadata["output_normalization"] = (
            validation_result.get("output_normalization")
            if isinstance(validation_result, dict)
            else None
        )
        metadata["output_decision"] = (
            validation_result.get("output_decision")
            if isinstance(validation_result, dict)
            else None
        )
        metadata["abstention_present"] = (
            validation_result.get("abstention_present")
            if isinstance(validation_result, dict)
            else None
        )
        metadata["abstention_reason"] = (
            validation_result.get("abstention_reason")
            if isinstance(validation_result, dict)
            else None
        )
        metadata["abstention_recognized"] = (
            validation_result.get("abstention_recognized")
            if isinstance(validation_result, dict)
            else None
        )
        metadata["reparse"] = {
            "parser": "fenced_json_recovery_v1",
            "reparsed_at_utc": datetime.now(timezone.utc).isoformat(),
            "original_status": original_status,
            "original_failure_reason": original_failure_reason,
        }
        run_llm_batch.write_json(metadata_path, metadata)

    return {
        "raw_file": str(raw_path),
        "status": "updated" if write else "dry_run",
        "original_status": original_status,
        "original_failure_reason": original_failure_reason,
        "new_status": new_status,
        "new_failure_reason": new_failure_reason,
        "prompt_file": str(prompt_path),
        "output_normalization": (
            validation_result.get("output_normalization")
            if isinstance(validation_result, dict)
            else None
        ),
    }


#This function parses CLI arguments for reprocessing an existing Step 17 run directory.
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reparse existing Step 17 raw outputs with the current parser.")
    parser.add_argument("--run-dir", required=True, help="Step 17 model run directory containing raw/, parsed/, metadata/, failures/.")
    parser.add_argument("--prompt-dir", action="append", default=[], help="Prompt directory fallback. Can be repeated.")
    parser.add_argument("--include-accepted", action="store_true", help="Also reparse outputs whose metadata status is already accepted.")
    parser.add_argument("--write", action="store_true", help="Rewrite parsed/metadata/failure artifacts. Without this, only reports changes.")
    parser.add_argument("--skip-summary", action="store_true", help="Do not regenerate runtime_summary files after --write.")
    return parser.parse_args()


#This function removes stale runtime summary artifacts before writing a fresh summary.
def remove_existing_runtime_summaries(run_dir: Path) -> list[Path]:
    removed_paths = []
    for suffix in [".json", ".csv", ".md"]:
        summary_path = (run_dir / "runtime_summary").with_suffix(suffix)
        if summary_path.exists():
            summary_path.unlink()
            removed_paths.append(summary_path)
    return removed_paths


#This is the CLI entry point.
def main() -> None:
    args = parse_args()
    run_dir = Path(args.run_dir).expanduser()
    prompt_dirs = [Path(path).expanduser() for path in args.prompt_dir]
    raw_dir = run_dir / "raw"
    metadata_dir = run_dir / "metadata"
    if not raw_dir.is_dir():
        raise FileNotFoundError(f"Missing raw output directory: {raw_dir}")
    if not metadata_dir.is_dir():
        raise FileNotFoundError(f"Missing metadata directory: {metadata_dir}")

    results = []
    original_status_counts: dict[str, int] = {}
    accepted_with_stale_failure_artifacts = 0
    cleaned_stale_failure_artifacts = 0
    for metadata_path in sorted(metadata_dir.glob("*.metadata.json")):
        metadata = read_json(metadata_path)
        status = str(metadata.get("status") or "unknown")
        original_status_counts[status] = original_status_counts.get(status, 0) + 1
        if status == "accepted":
            output_stem = metadata_path.name.removesuffix(".metadata.json")
            failure_path = run_dir / "failures" / f"{output_stem}.failure.json"
            rejected_path = run_dir / "failures" / f"{output_stem}.rejected.json"
            output_paths = dict(metadata.get("output_paths") or {})
            stale_paths_present = failure_path.exists() or rejected_path.exists()
            stale_metadata_paths_present = "failure" in output_paths or "rejected_json" in output_paths
            if stale_paths_present or stale_metadata_paths_present:
                accepted_with_stale_failure_artifacts += 1
                if args.write:
                    removed_paths = remove_superseded_failure_artifacts(
                        failure_path=failure_path,
                        rejected_path=rejected_path,
                        output_paths=output_paths,
                    )
                    cleaned_stale_failure_artifacts += len(removed_paths)
                    metadata["output_paths"] = output_paths
                    run_llm_batch.write_json(metadata_path, metadata)

    for raw_path in sorted(raw_dir.glob("*.raw.txt")):
        metadata_path = metadata_dir / f"{raw_path.name.removesuffix('.raw.txt')}.metadata.json"
        if metadata_path.exists() and not args.include_accepted:
            metadata = read_json(metadata_path)
            if metadata.get("status") == "accepted":
                continue
        results.append(
            reparse_one_raw_output(
                raw_path=raw_path,
                run_dir=run_dir,
                prompt_dirs=prompt_dirs,
                write=args.write,
            )
        )

    counts: dict[str, int] = {}
    for result in results:
        key = str(result.get("new_status") or result.get("reason") or result.get("status"))
        counts[key] = counts.get(key, 0) + 1

    projected_status_counts = dict(original_status_counts)
    normalized_output_count = 0
    normalized_region_id_alias_count = 0
    normalized_redundant_region_id_field_count = 0
    normalized_numeric_string_count = 0
    remaining_failure_reasons: dict[str, int] = {}
    for result in results:
        original_status = result.get("original_status")
        new_status = result.get("new_status")
        if original_status != new_status and isinstance(original_status, str) and isinstance(new_status, str):
            projected_status_counts[original_status] = projected_status_counts.get(original_status, 0) - 1
            projected_status_counts[new_status] = projected_status_counts.get(new_status, 0) + 1
        normalization = result.get("output_normalization")
        alias_details = normalization.get("region_id_field_alias") if isinstance(normalization, dict) else None
        redundant_details = (
            normalization.get("redundant_region_id_and_field")
            if isinstance(normalization, dict)
            else None
        )
        numeric_details = (
            normalization.get("replacement_uint_numeric_string")
            if isinstance(normalization, dict)
            else None
        )
        normalization_applied = False
        if isinstance(alias_details, dict) and alias_details.get("applied"):
            normalization_applied = True
            normalized_region_id_alias_count += int(alias_details.get("normalized_edit_count") or 0)
        if isinstance(redundant_details, dict) and redundant_details.get("applied"):
            normalization_applied = True
            normalized_redundant_region_id_field_count += int(
                redundant_details.get("normalized_edit_count") or 0
            )
        if isinstance(numeric_details, dict) and numeric_details.get("applied"):
            normalization_applied = True
            normalized_numeric_string_count += int(numeric_details.get("normalized_edit_count") or 0)
        if normalization_applied:
            normalized_output_count += 1
        if new_status == "failed":
            reason = str(result.get("new_failure_reason") or "unknown")
            remaining_failure_reasons[reason] = remaining_failure_reasons.get(reason, 0) + 1

    print(f"Run dir: {run_dir}")
    print(f"Mode: {'write' if args.write else 'dry-run'}")
    print(f"Raw outputs considered: {len(results)}")
    print(f"Result counts: {counts}")
    print(f"Status counts before: {original_status_counts}")
    print(f"Status counts after: {projected_status_counts}")
    print(f"Outputs normalized: {normalized_output_count}")
    print(f"Header region-id aliases normalized: {normalized_region_id_alias_count}")
    print(
        "Redundant header region-id/field edits normalized: "
        f"{normalized_redundant_region_id_field_count}"
    )
    print(f"Header replacement numeric strings normalized: {normalized_numeric_string_count}")
    print(f"Remaining failures by reason: {remaining_failure_reasons}")
    print(f"Accepted outputs with stale failure artifacts: {accepted_with_stale_failure_artifacts}")
    if args.write:
        print(f"Stale failure artifacts removed from pre-existing accepted outputs: {cleaned_stale_failure_artifacts}")

    if args.write and not args.skip_summary:
        removed_paths = remove_existing_runtime_summaries(run_dir)
        if removed_paths:
            print("Removed stale runtime summaries:")
            for removed_path in removed_paths:
                print(f"  - {removed_path}")
        summarize_llm_runtime.summarize_run(
            run_dir=run_dir,
            prompt_dirs=prompt_dirs,
        )


if __name__ == "__main__":
    main()
