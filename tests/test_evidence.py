"""
tests/test_evidence.py
======================
ProtocolEvidence export: schema conformance and non-interference with the
existing IQ/OQ/PQ / HTML output.
"""

import json

import jsonschema
import pytest

from samd_toolkit.core import SaMDDevice, DeviceClass, SoftwareSafetyClass
from samd_toolkit.evidence import SCHEMA_FILE, ProtocolEvidence, export_evidence
from samd_toolkit.reports.html_reporter import HTMLReporter
from samd_toolkit.standards.iso14971 import RiskManagementFile
from samd_toolkit.validators.iq_oq_pq import IQOQPQGenerator


@pytest.fixture
def executed():
    device = SaMDDevice(
        name="CardioWatch AI",
        version="2.1.0",
        manufacturer="MedTech Corp",
        device_class=DeviceClass.CLASS_II,
        software_safety_class=SoftwareSafetyClass.CLASS_B,
        contains_ai_ml=True,
    )
    session = IQOQPQGenerator(device).generate_full_package()
    session.items[0].mark_passed("J. Smith", "Environment verified", "TR-001")
    session.items[1].mark_failed("J. Smith", "Unexpected service running", "DR-001")
    return session, RiskManagementFile(device)


def test_committed_schema_matches_model():
    committed = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    assert committed == ProtocolEvidence.model_json_schema()


def test_export_validates_against_committed_schema(executed, tmp_path):
    session, rmf = executed
    out = tmp_path / "evidence.json"
    export_evidence(session, rmf, requirement_ids=["SRS-1"], path=out)
    payload = json.loads(out.read_text(encoding="utf-8"))
    jsonschema.validate(
        payload,
        json.loads(SCHEMA_FILE.read_text(encoding="utf-8")),
        cls=jsonschema.Draft202012Validator,
    )
    assert payload["source"] == "samd-val-kit"
    assert payload["requirement_ids"] == ["SRS-1"]
    assert payload["iec_62304"]["safety_class"] == "B"
    assert payload["protocol"]["passed"] == 1 and payload["protocol"]["failed"] == 1
    assert payload["protocol"]["total"] == len(payload["protocol"]["items"])
    assert payload["iso_14971"]["hazards"] == [r.hazard for r in rmf.risks]
    assert "drift" not in payload and "fairness" not in payload


def test_rmf_is_optional(executed):
    session, _ = executed
    assert export_evidence(session).iso_14971 is None


def test_export_does_not_alter_existing_output(executed):
    session, rmf = executed
    reporter = HTMLReporter(session)  # timestamp fixed at construction
    snapshot = lambda: (  # noqa: E731
        [i.to_dict() for i in session.items],
        session.summary(),
        rmf.summary(),
        reporter.generate(),
    )
    before = snapshot()
    export_evidence(session, rmf)
    assert snapshot() == before
