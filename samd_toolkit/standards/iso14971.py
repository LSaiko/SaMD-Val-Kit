"""
samd_toolkit/standards/iso14971.py
====================================
ISO 14971:2019 — Risk Management for Medical Devices

ISO 14971 is the international standard for applying risk management to medical devices.
It is required by FDA (via QSR), EU MDR, and virtually all international jurisdictions.

Key concepts:
    - Risk = Probability of Harm × Severity of Harm
    - Risk Acceptability Matrix (ALARP principle)
    - Risk Management File (RMF) — required documentation artifact
    - Risk Benefit Analysis (for residual risks)

Real-world SaMD risk examples:
    Class I:  Wellness app shows incorrect step count → minimal harm
    Class II: ECG algorithm misses AF → stroke risk
    Class III: Closed-loop insulin over-doses → hypoglycemia → death
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict
from datetime import datetime, timezone


class Severity(Enum):
    """ISO 14971 Annex D — Harm Severity Categories."""
    NEGLIGIBLE    = 1   # No injury, inconvenience
    MINOR         = 2   # Temporary injury, first aid level
    SERIOUS       = 3   # Hospitalization, permanent impairment possible
    CRITICAL      = 4   # Life-threatening injury, permanent impairment
    CATASTROPHIC  = 5   # Death or permanent severe disability


class Probability(Enum):
    """ISO 14971 Annex D — Probability of Occurrence."""
    IMPROBABLE    = 1   # < 1 in 10,000,000 (10^-7)
    REMOTE        = 2   # 1 in 100,000 to 1 in 10,000,000
    OCCASIONAL    = 3   # 1 in 100 to 1 in 100,000
    PROBABLE      = 4   # 1 in 10 to 1 in 100
    FREQUENT      = 5   # > 1 in 10


class RiskAcceptability(Enum):
    """ISO 14971 §6.4 — Risk acceptability determination."""
    ACCEPTABLE   = "Acceptable"    # Risk acceptable; no further action required
    ALARP        = "ALARP"         # Reduce as low as reasonably practicable
    UNACCEPTABLE = "Unacceptable"  # Must reduce before release


# ---------------------------------------------------------------------------
# Risk Acceptability Matrix (5×5)
# ---------------------------------------------------------------------------

# Standard ALARP matrix per ISO 14971 Annex D example
# Rows = Probability (1-5), Columns = Severity (1-5)
RISK_MATRIX: Dict[tuple, RiskAcceptability] = {
    # (probability, severity): acceptability
    (1, 1): RiskAcceptability.ACCEPTABLE,
    (1, 2): RiskAcceptability.ACCEPTABLE,
    (1, 3): RiskAcceptability.ACCEPTABLE,
    (1, 4): RiskAcceptability.ALARP,
    (1, 5): RiskAcceptability.ALARP,
    (2, 1): RiskAcceptability.ACCEPTABLE,
    (2, 2): RiskAcceptability.ACCEPTABLE,
    (2, 3): RiskAcceptability.ALARP,
    (2, 4): RiskAcceptability.ALARP,
    (2, 5): RiskAcceptability.UNACCEPTABLE,
    (3, 1): RiskAcceptability.ACCEPTABLE,
    (3, 2): RiskAcceptability.ALARP,
    (3, 3): RiskAcceptability.ALARP,
    (3, 4): RiskAcceptability.UNACCEPTABLE,
    (3, 5): RiskAcceptability.UNACCEPTABLE,
    (4, 1): RiskAcceptability.ALARP,
    (4, 2): RiskAcceptability.ALARP,
    (4, 3): RiskAcceptability.UNACCEPTABLE,
    (4, 4): RiskAcceptability.UNACCEPTABLE,
    (4, 5): RiskAcceptability.UNACCEPTABLE,
    (5, 1): RiskAcceptability.ALARP,
    (5, 2): RiskAcceptability.UNACCEPTABLE,
    (5, 3): RiskAcceptability.UNACCEPTABLE,
    (5, 4): RiskAcceptability.UNACCEPTABLE,
    (5, 5): RiskAcceptability.UNACCEPTABLE,
}


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class RiskItem:
    """
    A single risk item in the Risk Management File (RMF).

    Follows ISO 14971:2019 §5 risk assessment process:
        1. Hazard identification
        2. Hazardous situation description
        3. Harm description
        4. Initial risk estimation
        5. Risk evaluation
        6. Risk control measures
        7. Residual risk evaluation
    """
    # --- Identification ---
    risk_id: str = ""
    hazard: str = ""                         # e.g., "Algorithm misclassification of AF"
    hazardous_situation: str = ""            # e.g., "Undetected atrial fibrillation"
    harm: str = ""                           # e.g., "Stroke due to delayed treatment"
    affected_users: str = "Patient"
    related_use_scenario: str = ""

    # --- Initial Risk (Before Controls) ---
    probability_before: int = 3              # Probability 1-5
    severity: int = 4                        # Severity 1-5

    # --- Risk Controls (ISO 14971 §6.2 — Inherently safe design > protective measures > information) ---
    risk_controls: List[str] = field(default_factory=list)
    control_type: str = ""                   # "Inherent Safety" | "Protective Measure" | "Information for Safety"

    # --- Residual Risk (After Controls) ---
    probability_after: int = 1               # Probability 1-5 after controls applied
    residual_risk_justification: str = ""    # Benefit-risk analysis justification

    # --- Metadata ---
    owner: str = ""
    review_date: Optional[datetime] = None
    verification_method: str = ""            # How risk control effectiveness is verified

    @property
    def initial_risk_score(self) -> int:
        return self.probability_before * self.severity

    @property
    def residual_risk_score(self) -> int:
        return self.probability_after * self.severity

    @property
    def initial_acceptability(self) -> RiskAcceptability:
        key = (self.probability_before, self.severity)
        if key not in RISK_MATRIX:
            raise ValueError(
                f"Invalid risk matrix key {key}: probability and severity must each be 1–5"
            )
        return RISK_MATRIX[key]

    @property
    def residual_acceptability(self) -> RiskAcceptability:
        key = (self.probability_after, self.severity)
        if key not in RISK_MATRIX:
            raise ValueError(
                f"Invalid risk matrix key {key}: probability and severity must each be 1–5"
            )
        return RISK_MATRIX[key]

    @property
    def risk_reduction_achieved(self) -> bool:
        """True if residual risk is lower than initial risk."""
        return self.residual_risk_score < self.initial_risk_score

    def to_dict(self) -> Dict:
        return {
            "Risk ID": self.risk_id,
            "Hazard": self.hazard,
            "Hazardous Situation": self.hazardous_situation,
            "Harm": self.harm,
            "Initial Probability": self.probability_before,
            "Severity": self.severity,
            "Initial Risk Score": self.initial_risk_score,
            "Initial Acceptability": self.initial_acceptability.value,
            "Risk Controls": "; ".join(self.risk_controls),
            "Control Type": self.control_type,
            "Residual Probability": self.probability_after,
            "Residual Risk Score": self.residual_risk_score,
            "Residual Acceptability": self.residual_acceptability.value,
            "Justification": self.residual_risk_justification,
            "Verification": self.verification_method,
        }


# ---------------------------------------------------------------------------
# Risk Management File (RMF)
# ---------------------------------------------------------------------------

class RiskManagementFile:
    """
    ISO 14971:2019 §3.17 — Risk Management File (RMF).

    The RMF is a mandatory output of the risk management process.
    It must be maintained throughout the device lifecycle.

    Pre-populated with representative SaMD risks by device class.
    """

    def __init__(self, device):
        self.device = device
        self.risks: List[RiskItem] = []
        self.created_at = datetime.now(timezone.utc)
        self._prepopulate_typical_risks()

    def add_risk(self, risk: RiskItem) -> None:
        """Add a custom risk item to the file."""
        if not risk.risk_id:
            risk.risk_id = f"RISK-{len(self.risks) + 1:03d}"
        self.risks.append(risk)

    def _prepopulate_typical_risks(self):
        """
        Pre-populate with representative SaMD risks.
        Based on FDA iRASS database common SaMD failure modes and
        published literature on medical device software failures.
        """
        from ..core import DeviceClass

        # --- Universal SaMD Risks (all classes) ---
        self.add_risk(RiskItem(
            hazard="Software crash / unexpected termination",
            hazardous_situation="Clinical workflow interrupted during active patient monitoring",
            harm="Delayed diagnosis or treatment decision",
            probability_before=3, severity=3,
            risk_controls=[
                "Exception handling for all critical paths (IEC 62304 §5.5.3)",
                "Automated watchdog process with auto-restart",
                "Clear error messaging with recovery instructions in IFU"
            ],
            control_type="Inherent Safety + Information for Safety",
            probability_after=1,
            residual_risk_justification="Watchdog reduces occurrence; harm is delayed treatment, not direct injury",
            verification_method="Fault injection testing; soak test §OQ-003",
        ))

        self.add_risk(RiskItem(
            hazard="Data integrity failure — corrupted patient data",
            hazardous_situation="Corrupted data displayed as valid clinical result",
            harm="Incorrect clinical decision based on corrupt data",
            probability_before=2, severity=4,
            risk_controls=[
                "CRC/hash verification on all stored clinical data",
                "Database transaction integrity with ACID compliance",
                "Data validation on retrieval with error indication to user"
            ],
            control_type="Inherent Safety",
            probability_after=1,
            residual_risk_justification="ACID + hash verification makes silent corruption effectively impossible",
            verification_method="Data integrity testing §OQ-011",
        ))

        self.add_risk(RiskItem(
            hazard="Unauthorized access to PHI",
            hazardous_situation="Attacker gains access to patient health records",
            harm="Privacy breach; potential use for insurance/employment discrimination",
            probability_before=3, severity=3,
            risk_controls=[
                "AES-256 encryption at rest; TLS 1.3 in transit",
                "MFA required for all clinical user accounts",
                "Role-based access control with principle of least privilege",
                "Audit logging of all PHI access"
            ],
            control_type="Protective Measure",
            probability_after=1,
            residual_risk_justification="Defense-in-depth reduces breach probability; HIPAA breach notification as backstop",
            verification_method="Penetration test §PQ-007; access control test §OQ-008",
        ))

        # --- Class II/III specific risks ---
        from ..core import DeviceClass
        if self.device.device_class in (DeviceClass.CLASS_II, DeviceClass.CLASS_III):
            self.add_risk(RiskItem(
                hazard="Algorithm false negative — failure to detect critical condition",
                hazardous_situation=f"Device reports 'normal' when patient has critical finding",
                harm="Delayed treatment of serious condition (e.g., undetected AF → stroke)",
                probability_before=3, severity=5,
                risk_controls=[
                    "Clinical validation on diverse population dataset (sensitivity ≥ spec)",
                    "Physician review required before treatment decision (non-autonomous output)",
                    "Mandatory disclosure of sensitivity/specificity metrics in IFU",
                    "Post-market surveillance plan with sensitivity monitoring and MDR trigger",
                    "User training on device limitations and false negative rate"
                ],
                control_type="Protective Measure + Information for Safety",
                probability_after=1,
                residual_risk_justification=(
                    "Mandatory physician review before any clinical action means the device "
                    "is an aid, not a standalone diagnostic — physician oversight reduces "
                    "harm probability to improbable; residual risk ALARP with clear benefit."
                ),
                verification_method="Clinical validation study §PQ-006; sensitivity metric monitoring",
            ))

            self.add_risk(RiskItem(
                hazard="Algorithm false positive — over-detection of benign findings",
                hazardous_situation="Device generates alert for non-existent condition",
                harm="Unnecessary patient anxiety; unnecessary diagnostic procedures; alert fatigue",
                probability_before=3, severity=2,
                risk_controls=[
                    "Specificity target ≥ spec in clinical validation",
                    "Alert threshold tuning with clinical advisory panel",
                    "Clinician training on positive predictive value"
                ],
                control_type="Inherent Safety + Information for Safety",
                probability_after=2,
                residual_risk_justification="Harm is inconvenience/unnecessary testing; acceptable given benefit",
                verification_method="Clinical validation §PQ-006; specificity metric",
            ))

        # --- Class III specific risks ---
        if self.device.device_class == DeviceClass.CLASS_III:
            self.add_risk(RiskItem(
                hazard="Autonomous treatment recommendation — over/under dosing",
                hazardous_situation="Closed-loop algorithm recommends incorrect drug dose",
                harm="Hypoglycemia (overdose) or hyperglycemia (underdose) — life-threatening",
                probability_before=2, severity=5,
                risk_controls=[
                    "Hard-coded clinical safety limits cannot be overridden by algorithm",
                    "Dose change rate limiting (maximum delta per time window)",
                    "Mandatory physician review for all doses exceeding safety threshold",
                    "Real-time patient monitoring with clinical escalation pathway",
                    "Fail-safe mode: halt autonomous dosing if sensor data lost"
                ],
                control_type="Inherent Safety + Protective Measure",
                probability_after=1,
                residual_risk_justification=(
                    "Multiple independent safety limits; physician oversight; "
                    "benefit-risk strongly positive for intended population"
                ),
                verification_method="Safety limit testing; fault injection; clinical trial data",
            ))

        # --- AI/ML specific risks ---
        if self.device.contains_ai_ml:
            self.add_risk(RiskItem(
                hazard="AI/ML model drift — performance degradation over time",
                hazardous_situation="Production model performance degrades below clinical threshold post-deployment",
                harm="Increased false negatives/positives; incorrect clinical guidance",
                probability_before=3, severity=4,
                risk_controls=[
                    "Continuous performance monitoring dashboard with drift alerts",
                    "Predetermined Change Control Plan (PCCP) per FDA AI/ML guidance",
                    "Model retraining and revalidation protocol",
                    "Version-locked model in production with change management process"
                ],
                control_type="Protective Measure",
                probability_after=2,
                residual_risk_justification="Monitoring catches drift before harm; PCCP enables controlled updates",
                verification_method="PQ-008 AI/ML production monitoring baseline",
            ))

    @property
    def unacceptable_risks(self) -> List[RiskItem]:
        return [r for r in self.risks if r.residual_acceptability == RiskAcceptability.UNACCEPTABLE]

    @property
    def alarp_risks(self) -> List[RiskItem]:
        return [r for r in self.risks if r.residual_acceptability == RiskAcceptability.ALARP]

    @property
    def overall_residual_risk_acceptable(self) -> bool:
        """Per ISO 14971 §8: Overall residual risk acceptable if no UNACCEPTABLE residual risks."""
        return len(self.unacceptable_risks) == 0

    def summary(self) -> Dict:
        return {
            "Device": self.device.name,
            "Standard": "ISO 14971:2019",
            "Total Risks": len(self.risks),
            "Unacceptable Residual Risks": len(self.unacceptable_risks),
            "ALARP Residual Risks": len(self.alarp_risks),
            "Overall Residual Risk": "ACCEPTABLE" if self.overall_residual_risk_acceptable else "UNACCEPTABLE — ACTION REQUIRED",
        }

    def print_summary(self):
        print("\n" + "="*70)
        print("ISO 14971:2019 RISK MANAGEMENT FILE SUMMARY")
        print("="*70)
        for k, v in self.summary().items():
            print(f"  {k:<35} {v}")
        print("\nRisk Register:")
        print(f"  {'ID':<12} {'Initial':<10} {'Residual':<12} {'Hazard'}")
        print("  " + "-"*65)
        for r in self.risks:
            print(f"  {r.risk_id:<12} {r.initial_acceptability.value:<10} {r.residual_acceptability.value:<12} {r.hazard[:45]}")
        print()
