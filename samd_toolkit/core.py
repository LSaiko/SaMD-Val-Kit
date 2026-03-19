"""
samd_toolkit/core.py
====================
Core data models for SaMD Validation Toolkit.

Covers:
- FDA Device Classes I, II, III
- IEC 62304 Software Safety Classes A, B, C
- IMDRF SaMD Risk Categories I–IV
- ISO 14971 Risk levels
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict
from datetime import datetime
import uuid


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class DeviceClass(Enum):
    """FDA device classification per 21 CFR Part 862-892."""
    CLASS_I   = "I"    # General controls; low risk; e.g., bandage, tongue depressor
    CLASS_II  = "II"   # Special controls + 510(k); moderate risk; e.g., ECG monitor
    CLASS_III = "III"  # PMA required; high risk; e.g., implantable cardiac device


class SoftwareSafetyClass(Enum):
    """
    IEC 62304:2006+AMD1:2015 — Software Safety Classification.

    Class A: No injury or damage to health is possible.
    Class B: Non-serious injury is possible.
    Class C: Death or serious injury is possible.
    """
    CLASS_A = "A"   # Lowest — wellness apps, administrative SaMD
    CLASS_B = "B"   # Moderate — diagnostic support, monitoring (non-critical path)
    CLASS_C = "C"   # Highest — treatment control, closed-loop, life-critical


class IMDRFCategory(Enum):
    """
    IMDRF SaMD N12 Risk Categorization Framework.

    Axes: (State of Healthcare Situation) × (Significance of SaMD Output)
    Category I (lowest) → Category IV (highest)
    """
    CATEGORY_I   = "I"    # Inform / non-serious condition
    CATEGORY_II  = "II"   # Inform / serious OR Drive/Treat / non-serious
    CATEGORY_III = "III"  # Drive/Treat / serious OR Diagnose / critical
    CATEGORY_IV  = "IV"   # Treat or Diagnose / critical or life-threatening


class RegulatoryPathway(Enum):
    """FDA regulatory submission pathways for SaMD."""
    EXEMPT       = "Exempt"       # Class I exempt (most Class I)
    K510         = "510(k)"       # Premarket Notification (most Class II)
    DE_NOVO      = "De Novo"      # Novel low-to-moderate risk, no predicate
    PMA          = "PMA"          # Premarket Approval (Class III)
    EUA          = "EUA"          # Emergency Use Authorization
    HDE          = "HDE"          # Humanitarian Device Exemption


class ValidationStatus(Enum):
    """Status of a validation protocol or checklist item."""
    NOT_STARTED = "Not Started"
    IN_PROGRESS = "In Progress"
    PASSED      = "Passed"
    FAILED      = "Failed"
    WAIVED      = "Waived"
    N_A         = "N/A"


class RiskLevel(Enum):
    """ISO 14971 risk acceptability levels."""
    ACCEPTABLE    = "Acceptable"
    ALARP         = "ALARP"          # As Low As Reasonably Practicable
    UNACCEPTABLE  = "Unacceptable"


# ---------------------------------------------------------------------------
# Core Device Model
# ---------------------------------------------------------------------------

@dataclass
class SaMDDevice:
    """
    Represents a Software as a Medical Device (SaMD) product.

    Example real-world devices:
        Class I:   Apple Watch Activity (wellness only, non-clinical output)
        Class II:  iRhythm Zio AT (K192613) — AI-driven ECG arrhythmia detection
        Class III: Medtronic CareLink — Remote monitoring for implantable CRM devices
                   Viz.ai LVO — AI stroke detection (De Novo DEN180044)
    """
    # --- Identity ---
    name: str
    version: str
    manufacturer: str

    # --- Classification ---
    device_class: DeviceClass
    software_safety_class: SoftwareSafetyClass
    imdrf_category: Optional[IMDRFCategory] = None
    regulatory_pathway: Optional[RegulatoryPathway] = None

    # --- Regulatory Identifiers ---
    predicate_device: Optional[str]  = None   # e.g., "iRhythm Zio AT (K192613)"
    product_code: Optional[str]      = None   # FDA 3-letter product code, e.g., "MQP"
    fda_submission_number: Optional[str] = None

    # --- Device Description ---
    intended_use: str = ""
    indications_for_use: str = ""
    contraindications: str = ""
    intended_users: List[str] = field(default_factory=list)  # e.g., ["HCP", "Patient"]

    # --- Technical Metadata ---
    programming_language: str = ""
    operating_system: str = ""
    deployment_environment: str = ""   # Cloud, On-Premise, Embedded, Hybrid
    interfaces: List[str] = field(default_factory=list)  # e.g., ["REST API", "HL7 FHIR"]

    # --- Cybersecurity ---
    network_connected: bool = True
    contains_ai_ml: bool = False
    processes_phi: bool = True          # Protected Health Information (HIPAA)
    interoperates_with_ehr: bool = False

    # --- Lifecycle ---
    created_at: datetime = field(default_factory=datetime.now)
    uid: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):
        """Auto-infer IMDRF category and regulatory pathway if not set."""
        if self.imdrf_category is None:
            self.imdrf_category = self._infer_imdrf_category()
        if self.regulatory_pathway is None:
            self.regulatory_pathway = self._infer_pathway()

    def _infer_imdrf_category(self) -> IMDRFCategory:
        """Map FDA device class to approximate IMDRF category."""
        mapping = {
            DeviceClass.CLASS_I:   IMDRFCategory.CATEGORY_I,
            DeviceClass.CLASS_II:  IMDRFCategory.CATEGORY_II,
            DeviceClass.CLASS_III: IMDRFCategory.CATEGORY_IV,
        }
        return mapping[self.device_class]

    def _infer_pathway(self) -> RegulatoryPathway:
        """Infer most common regulatory pathway by device class."""
        mapping = {
            DeviceClass.CLASS_I:   RegulatoryPathway.EXEMPT,
            DeviceClass.CLASS_II:  RegulatoryPathway.K510,
            DeviceClass.CLASS_III: RegulatoryPathway.PMA,
        }
        return mapping[self.device_class]

    @property
    def risk_label(self) -> str:
        """Human-readable risk description."""
        labels = {
            DeviceClass.CLASS_I:   "Low Risk — General Controls",
            DeviceClass.CLASS_II:  "Moderate Risk — Special Controls + 510(k)",
            DeviceClass.CLASS_III: "High Risk — Premarket Approval (PMA)",
        }
        return labels[self.device_class]

    def summary(self) -> Dict:
        """Return a structured summary dict for reporting."""
        return {
            "Device Name": self.name,
            "Version": self.version,
            "Manufacturer": self.manufacturer,
            "FDA Class": self.device_class.value,
            "Risk Level": self.risk_label,
            "IEC 62304 Safety Class": self.software_safety_class.value,
            "IMDRF Category": self.imdrf_category.value if self.imdrf_category else "N/A",
            "Regulatory Pathway": self.regulatory_pathway.value if self.regulatory_pathway else "N/A",
            "Intended Use": self.intended_use,
            "AI/ML Enabled": self.contains_ai_ml,
            "Network Connected": self.network_connected,
            "Processes PHI": self.processes_phi,
        }


# ---------------------------------------------------------------------------
# Validation Session
# ---------------------------------------------------------------------------

@dataclass
class ValidationItem:
    """A single checklist item or test step within a validation protocol."""
    item_id: str
    section: str
    requirement: str
    acceptance_criteria: str
    test_method: str
    reference_standard: str         # e.g., "IEC 62304 §5.1.1"
    status: ValidationStatus = ValidationStatus.NOT_STARTED
    actual_result: str = ""
    tester: str = ""
    test_date: Optional[datetime] = None
    evidence_ref: str = ""           # Document or test case reference
    deviation_note: str = ""

    def mark_passed(self, tester: str, result: str, evidence: str = "") -> None:
        self.status = ValidationStatus.PASSED
        self.actual_result = result
        self.tester = tester
        self.test_date = datetime.now()
        self.evidence_ref = evidence

    def mark_failed(self, tester: str, result: str, deviation: str = "") -> None:
        self.status = ValidationStatus.FAILED
        self.actual_result = result
        self.tester = tester
        self.test_date = datetime.now()
        self.deviation_note = deviation

    def to_dict(self) -> Dict:
        return {
            "ID": self.item_id,
            "Section": self.section,
            "Requirement": self.requirement,
            "Acceptance Criteria": self.acceptance_criteria,
            "Test Method": self.test_method,
            "Reference": self.reference_standard,
            "Status": self.status.value,
            "Actual Result": self.actual_result,
            "Tester": self.tester,
            "Test Date": self.test_date.isoformat() if self.test_date else "",
            "Evidence": self.evidence_ref,
            "Deviation": self.deviation_note,
        }


@dataclass
class ValidationSession:
    """
    Tracks a complete validation execution session for a SaMD device.

    Stores IQ, OQ, and PQ items together with metadata for audit trail.
    """
    device: SaMDDevice
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    protocol_type: str = "IQ/OQ/PQ"
    prepared_by: str = ""
    approved_by: str = ""
    site: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    items: List[ValidationItem] = field(default_factory=list)

    def add_item(self, item: ValidationItem) -> None:
        self.items.append(item)

    def get_by_section(self, section: str) -> List[ValidationItem]:
        return [i for i in self.items if i.section == section]

    @property
    def total(self) -> int:
        return len(self.items)

    @property
    def passed(self) -> int:
        return sum(1 for i in self.items if i.status == ValidationStatus.PASSED)

    @property
    def failed(self) -> int:
        return sum(1 for i in self.items if i.status == ValidationStatus.FAILED)

    @property
    def pending(self) -> int:
        return sum(1 for i in self.items
                   if i.status in (ValidationStatus.NOT_STARTED, ValidationStatus.IN_PROGRESS))

    @property
    def pass_rate(self) -> float:
        executed = self.total - self.pending
        return (self.passed / executed * 100) if executed > 0 else 0.0

    def summary(self) -> Dict:
        return {
            "Session ID": self.session_id,
            "Device": self.device.name,
            "Version": self.device.version,
            "Protocol": self.protocol_type,
            "Prepared By": self.prepared_by,
            "Approved By": self.approved_by,
            "Site": self.site,
            "Date": self.created_at.isoformat(),
            "Total Items": self.total,
            "Passed": self.passed,
            "Failed": self.failed,
            "Pending": self.pending,
            "Pass Rate": f"{self.pass_rate:.1f}%",
        }
