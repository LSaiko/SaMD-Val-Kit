"""
samd_toolkit/evidence.py
========================
Machine-readable protocol evidence export for traceability-matrix-dhf.

Additive: reads an existing ValidationSession / RiskManagementFile and never
mutates them, so IQ/OQ/PQ, HTML and SPDX output are unchanged.

Schema family: shares the envelope (schema_version, generated_at, evidence_id,
requirement_ids) and the iec_62304 / iso_14971 block shapes with
ml-samd-validator's ValidationEvidence. It is NOT a ValidationEvidence payload:
this toolkit produces no model drift, fairness or performance baseline, so
those blocks are absent rather than fabricated. The IQ/OQ/PQ execution record
(21 CFR 820.30(f)/(g), IEC 62304 §5.7) is carried in ``protocol`` instead.

Requires the optional extra: pip install "samd-validation-toolkit[evidence]"
"""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from .core import ValidationSession, _utcnow
from .standards.iso14971 import RiskManagementFile

SCHEMA_FILE = Path(__file__).resolve().parent / "protocol-evidence.schema.json"

# IEC 62304:2006+AMD1:2015 §4.3 class definitions.
_SAFETY_CLASS_RATIONALE = {
    "A": "IEC 62304 §4.3 Class A: no injury or damage to health is possible.",
    "B": "IEC 62304 §4.3 Class B: non-serious injury is possible.",
    "C": "IEC 62304 §4.3 Class C: death or serious injury is possible.",
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DeviceIdentity(_Strict):
    name: str
    version: str
    manufacturer: str
    fda_class: Literal["I", "II", "III"]
    regulatory_pathway: Optional[str] = None
    imdrf_category: Optional[str] = None


class Iec62304Classification(_Strict):
    safety_class: Literal["A", "B", "C"]
    rationale: str


class Iso14971Summary(_Strict):
    hazards: List[str]
    risk_controls: List[str]
    residual_risk_statement: str


class ProtocolItemResult(_Strict):
    item_id: str
    section: str
    requirement: str
    reference_standard: str
    status: Literal["Not Started", "In Progress", "Passed", "Failed", "Waived", "N/A"]
    tester: str = ""
    test_date: Optional[datetime] = None
    evidence_ref: str = ""
    deviation_note: str = ""


class ProtocolExecution(_Strict):
    protocol_type: str
    session_id: str
    total: int
    passed: int
    failed: int
    pending: int
    items: List[ProtocolItemResult]


class ProtocolEvidence(_Strict):
    """Stable JSON export of an IQ/OQ/PQ session for traceability-matrix-dhf."""

    schema_version: Literal["1.0"] = "1.0"
    source: Literal["samd-val-kit"] = "samd-val-kit"
    generated_at: datetime
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    requirement_ids: List[str] = Field(default_factory=list)
    device: DeviceIdentity
    iec_62304: Iec62304Classification
    iso_14971: Optional[Iso14971Summary] = None
    protocol: ProtocolExecution


def export_evidence(
    session: ValidationSession,
    rmf: Optional[RiskManagementFile] = None,
    requirement_ids: Optional[List[str]] = None,
    path: Optional[Path] = None,
) -> ProtocolEvidence:
    """Build a ProtocolEvidence from an existing session; write JSON to ``path`` if given."""
    d = session.device
    evidence = ProtocolEvidence(
        generated_at=_utcnow(),
        requirement_ids=list(requirement_ids or []),
        device=DeviceIdentity(
            name=d.name,
            version=d.version,
            manufacturer=d.manufacturer,
            fda_class=d.device_class.value,
            regulatory_pathway=(
                d.regulatory_pathway.value if d.regulatory_pathway else None
            ),
            imdrf_category=d.imdrf_category.value if d.imdrf_category else None,
        ),
        iec_62304=Iec62304Classification(
            safety_class=d.software_safety_class.value,
            rationale=_SAFETY_CLASS_RATIONALE[d.software_safety_class.value],
        ),
        iso_14971=_risk_summary(rmf) if rmf else None,
        protocol=ProtocolExecution(
            protocol_type=session.protocol_type,
            session_id=session.session_id,
            total=session.total,
            passed=session.passed,
            failed=session.failed,
            pending=session.pending,
            items=[
                ProtocolItemResult(
                    item_id=i.item_id,
                    section=i.section,
                    requirement=i.requirement,
                    reference_standard=i.reference_standard,
                    status=i.status.value,
                    tester=i.tester,
                    test_date=i.test_date,
                    evidence_ref=i.evidence_ref,
                    deviation_note=i.deviation_note,
                )
                for i in session.items
            ],
        ),
    )
    if path is not None:
        Path(path).write_text(evidence.model_dump_json(indent=2), encoding="utf-8")
    return evidence


def _risk_summary(rmf: RiskManagementFile) -> Iso14971Summary:
    verdict = "" if rmf.overall_residual_risk_acceptable else "NOT "
    statement = (
        f"ISO 14971 §8: {len(rmf.risks)} risk(s) evaluated; "
        f"{len(rmf.unacceptable_risks)} unacceptable, {len(rmf.alarp_risks)} ALARP residual. "
        f"Overall residual risk {verdict}acceptable."
    )
    return Iso14971Summary(
        hazards=[r.hazard for r in rmf.risks],
        risk_controls=sorted({c for r in rmf.risks for c in r.risk_controls}),
        residual_risk_statement=statement,
    )
