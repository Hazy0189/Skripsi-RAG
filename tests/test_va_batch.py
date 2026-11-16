from copy import deepcopy
from unittest.mock import Mock

import pytest

from skripsi_rag.va_batch import run_va_batch, batch_rows
from skripsi_rag.va_import import parse_acunetix_csv
from test_va_import import csv_bytes, finding

ASSETS = {"A": {"asset_id": "A"}, "B": {"asset_id": "B"}}
NVD = {"cve_id": "CVE-2024-1234", "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}


def test_dedup_retains_occurrences_and_keeps_targets_components_assets_separate():
    rows = [finding(), finding(Affects="/two"), finding(Target="https://other.test"),
            finding(ModuleName="other-component"), finding(CVEList='""'), finding(Target="unknown")]
    report = parse_acunetix_csv(csv_bytes(rows))
    fetcher = Mock(return_value=(NVD, "cached"))
    assessor = Mock(return_value={"status": "needs_verification", "applicability": {"status": "Unknown"},
                                 "base_score": 9.8, "investigation_priority": "P2"})
    batch = run_va_batch(report, {rows[0]["Target"]: "A", "https://other.test": "B"}, ASSETS,
                         cloud_consent=True, fetcher=fetcher, assessor=assessor)
    assert len(batch["cases"]) == 6
    assert fetcher.call_count == 1
    assert assessor.call_count == 3
    assert [c["status"] for c in batch["cases"]][-2:] == ["no_cve", "unmapped_asset"]
    assert "Name" not in str(assessor.call_args)
    assert all(row["Priority"] is None for row in batch_rows(batch))


def test_consent_blocks_all_network_calls():
    fetcher = Mock()
    with pytest.raises(ValueError, match="consent"):
        run_va_batch(parse_acunetix_csv(csv_bytes([finding()])), {finding()["Target"]: "A"}, ASSETS,
                     fetcher=fetcher)
    fetcher.assert_not_called()


def test_no_cve_and_false_positive_can_be_processed_without_cloud_calls():
    fetcher = Mock()
    report = parse_acunetix_csv(csv_bytes([finding(CVEList='""'), finding(IsFalsePositive="true")]))
    batch = run_va_batch(report, {finding()["Target"]: "A"}, ASSETS, fetcher=fetcher)
    assert [c["status"] for c in batch["cases"]] == ["no_cve", "false_positive"]
    fetcher.assert_not_called()


def test_partial_failures_missing_nvd_and_conflicts_remain_visible():
    rows = [finding(), finding(CVEList="CVE-2024-9999"), finding(CVEList="CVE-2024-8888"),
            finding(CVEList="CVE-2024-7777"), finding(CVEList="CVE-2024-6666")]
    report = parse_acunetix_csv(csv_bytes(rows))
    def fetch(cve):
        if cve.endswith("9999"):
            return None, "missing"
        nvd = deepcopy(NVD)
        nvd["cve_id"] = cve
        if cve.endswith("8888"):
            nvd["vector_string"] = ""
        return nvd, "ok"
    def assess(nvd, asset, **kwargs):
        if nvd["cve_id"].endswith("7777"):
            raise RuntimeError("sensitive API error")
        return {"status": "not_applicable", "applicability": {"status": "Not Applicable"}}
    batch = run_va_batch(report, {finding()["Target"]: "A"}, ASSETS, cloud_consent=True,
                         fetcher=fetch, assessor=assess)
    assert [c["status"] for c in batch["cases"]] == ["scanner_inventory_conflict", "nvd_unavailable",
        "unsupported_or_missing_nvd_cvss", "failed", "scanner_inventory_conflict"]
    assert "sensitive API error" not in str(batch)


def test_one_finding_with_multiple_cves_keeps_each_assessment():
    report = parse_acunetix_csv(csv_bytes([finding(CVEList="CVE-2024-1234,CVE-2024-5678")]))
    batch = run_va_batch(report, {finding()["Target"]: "A"}, ASSETS, cloud_consent=True,
        fetcher=lambda cve: ({**NVD, "cve_id": cve}, "ok"),
        assessor=lambda *args, **kwargs: {"status": "failed", "applicability": None})
    assert len(batch["cases"]) == 2
    assert len({c["finding_id"] for c in batch["cases"]}) == 1


def test_shared_assessment_history_preserves_all_endpoint_occurrences():
    from skripsi_rag.va_batch import case_history_record
    report = parse_acunetix_csv(csv_bytes([finding(), finding(Affects="/two")]))
    assessment = {"status": "needs_verification", "run_id": "shared", "created_at": "2026-11-16T00:00:00+00:00",
        "base_score": 9.8, "base_vector": NVD["vector_string"], "inputs": {"description": "NVD fixture"},
        "applicability": {"status": "Unknown"}}
    batch = run_va_batch(report, {finding()["Target"]: "A"}, ASSETS, cloud_consent=True,
        fetcher=lambda cve: (NVD, "ok"), assessor=lambda *args, **kwargs: assessment)
    record = case_history_record(batch, batch["cases"][0], ASSETS["A"])
    assert len(record.evidence["scanner_occurrences"]) == 2
    assert record.provenance["report_sha256"] == report["report_id"]
