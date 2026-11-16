"""Operational VA batch triage, independent of Streamlit and experiment splits."""
from datetime import datetime, timezone
import uuid


def run_va_batch(report, target_assets, assets, *, api_key="", model=None,
                 context_store=None, cloud_consent=False, relevance_threshold=0.15,
                 top_k=3, fetcher=None, assessor=None, on_progress=None):
    """Assess each distinct target/component/asset/CVE; keep every occurrence.

    Acunetix finding data remains local provenance, never LLM input. Scanner
    scores never substitute NVD metrics or confirm software applicability.
    """
    actionable = any(f["import_status"] == "ready" and f["cve_ids"]
                     and assets.get(target_assets.get(f["target"])) for f in report["findings"])
    if actionable and cloud_consent is not True:
        raise ValueError("Explicit cloud consent is required before batch analysis.")
    from skripsi_rag.nvd_client import fetch_cve_from_nvd
    from skripsi_rag.pipeline import run_assessment
    from skripsi_rag.llm_assessment import DEFAULT_MODEL
    fetcher = fetcher or fetch_cve_from_nvd
    assessor = assessor or run_assessment
    batch = {"batch_id": str(uuid.uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
             "report": report, "target_assets": dict(target_assets), "cases": []}
    nvd_cache = {}
    assessment_cache = {}
    for index, finding in enumerate(report["findings"]):
        target = finding["target"]
        asset_id = target_assets.get(target, "")
        asset = assets.get(asset_id)
        for cve in finding["cve_ids"] or [None]:
            case = {"finding_id": finding["finding_id"], "cve_id": cve, "asset_id": asset_id,
                    "status": None, "assessment": None, "issues": list(finding["issues"])}
            batch["cases"].append(case)
            if finding["import_status"] != "ready":
                case["status"] = finding["import_status"]
                continue
            if not cve:
                case["status"] = "no_cve"
                continue
            if not asset or asset.get("asset_id") != asset_id:
                case["status"] = "unmapped_asset"
                continue
            if cve not in nvd_cache:
                try:
                    nvd_cache[cve] = fetcher(cve)[0]
                except Exception:
                    nvd_cache[cve] = None
            nvd = nvd_cache[cve]
            if not nvd or nvd.get("cve_id") != cve:
                case["status"] = "nvd_unavailable"
                continue
            if not nvd.get("vector_string"):
                case["status"] = "unsupported_or_missing_nvd_cvss"
                continue
            # Reusing a CVE assessment across targets or scanner modules can mix asset context.
            key = (target, asset_id, finding["module"] or finding["name"], cve)
            if key not in assessment_cache:
                try:
                    assessment_cache[key] = assessor(nvd, asset, api_key=api_key,
                        experiment_id="E3", context_store=context_store, model=model or DEFAULT_MODEL,
                        relevance_threshold=relevance_threshold, top_k=top_k, cloud_consent=True)
                except Exception as exc:
                    assessment_cache[key] = {"status": "failed", "failures": [
                        {"stage": "assessment", "error_type": type(exc).__name__}]}
            assessment = assessment_cache[key]
            case["assessment"] = assessment
            case["status"] = assessment["status"]
            if (assessment.get("applicability") or {}).get("status") == "Not Applicable":
                case["status"] = "scanner_inventory_conflict"
                case["issues"].append("Scanner reports this CVE but inventory matching says Not Applicable; review both sources.")
        if on_progress:
            on_progress(index + 1, len(report["findings"]))
    return batch


def batch_rows(batch):
    findings = {f["finding_id"]: f for f in batch["report"]["findings"]}
    rows = []
    for case in batch["cases"]:
        f = findings[case["finding_id"]]
        a = case["assessment"] or {}
        rows.append({"Row": f["row_number"], "Finding": f["name"], "Target": f["target"],
                     "Location": f["affects"], "Asset": case["asset_id"], "CVE": case["cve_id"] or "",
                     "Scanner Severity": f["scanner_severity"], "Scanner CVSS": f["scanner_cvss_score"],
                     "NVD Base CVSS": a.get("base_score"), "Technical Severity": a.get("technical_severity"),
                     "Environmental CVSS": a.get("computed_environmental_score"),
                     "Environmental Severity": a.get("environmental_severity"),
                     "Contextual Score Status": a.get("contextual_score_status"),
                     "Priority": a.get("deterministic_priority"),
                     "Investigation Priority": a.get("investigation_priority"),
                     "Applicability": (a.get("applicability") or {}).get("status"),
                     "Status": case["status"], "Issues": " ".join(case["issues"])})
    return rows


def case_history_record(batch, case, asset):
    """Reuse the existing history schema; include scanner/report provenance."""
    from skripsi_rag.assessment_history import AssessmentRecord
    a = case["assessment"]
    priority = a.get("priority_result") or {}
    applicability = a.get("applicability") or {}
    retrieval = a.get("retrieval") or {}
    finding = next(f for f in batch["report"]["findings"] if f["finding_id"] == case["finding_id"])
    occurrence_ids = {c["finding_id"] for c in batch["cases"]
                      if c["assessment"] and c["assessment"].get("run_id") == a["run_id"]}
    occurrences = [f for f in batch["report"]["findings"] if f["finding_id"] in occurrence_ids]
    return AssessmentRecord(
        id=f"{batch['batch_id']}:{a['run_id']}", timestamp=a["created_at"],
        cve_id=case["cve_id"], asset_id=case["asset_id"], asset_name=asset.get("asset_name", ""),
        base_score=a["base_score"], context_score=a.get("computed_environmental_score"),
        priority=a.get("deterministic_priority"), llm_priority=a.get("llm_priority"),
        vector_string=a["base_vector"], modified_vector=a.get("computed_environmental_vector") or "",
        retrieval_confidence=max(a.get("retrieval_scores") or [], default=None),
        evidence={"nvd": {"description": a["inputs"]["description"], "vector_string": a["base_vector"],
                          "nvd_snapshot_id": a.get("nvd_snapshot_id"), "nvd_cvss_source": a.get("nvd_cvss_source")},
                  "document_retrieval": retrieval, "model_context": (a.get("model_input") or {}).get("asset_context", {}),
                  "llm_justification": (a.get("model_output") or {}).get("justification", ""),
                  "scanner_finding": finding, "scanner_occurrences": occurrences},
        applicability=applicability.get("status"), applicability_explanation=applicability.get("explanation"),
        applicability_evidence=applicability.get("evidence", []),
        priority_status=priority.get("status"), priority_score=priority.get("score"),
        priority_explanation=priority.get("explanation"), priority_missing_evidence=priority.get("missing_evidence"),
        priority_unknown_factors=priority.get("unknown_factors"), priority_contributions=priority.get("rule_contributions"),
        investigation_priority=a.get("investigation_priority"), rubric_version=a.get("rubric_version"),
        model_output=a.get("model_output"),
        provenance={"batch_id": batch["batch_id"], "report_sha256": batch["report"]["report_id"],
                    "source": "Acunetix CSV", "finding_id": finding["finding_id"],
                    "case_status": case["status"], "case_issues": case["issues"],
                    "model_input": a.get("model_input"), "model": a.get("llm_model"),
                    "contextual_score_status": a.get("contextual_score_status"), "assessment": a})
