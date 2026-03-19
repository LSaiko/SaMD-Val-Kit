"""
samd_toolkit/standards/imdrf.py
=================================
IMDRF SaMD Risk Categorization Framework

References:
- IMDRF/SaMD WG/N10FINAL:2013 — SaMD: Key Definitions
- IMDRF/SaMD WG/N12FINAL:2014 — SaMD: Possible Framework for Risk Categorization
- IMDRF/SaMD WG/N23FINAL:2015 — SaMD: Clinical Evaluation
- FDA "Software as a Medical Device (SaMD): Clinical Evaluation" Guidance (2017)

IMDRF Two-Axis Risk Framework:
    Axis 1: State of Healthcare Situation / Condition
        - Critical:     Immediately life-threatening or irreversible condition
        - Serious:      Long-term harm or requiring intervention to prevent deterioration
        - Non-Serious:  No long-term harm expected

    Axis 2: Significance of SaMD Information to Healthcare Decision
        - Treat or Diagnose: SaMD output drives or is the direct basis for treatment/Dx
        - Drive Clinical Management: Informs next diagnostic/therapeutic intervention
        - Inform Clinical Management: Aids diagnosis; clinician makes independent decision

    Resulting Categories:
        ┌─────────────────┬───────────────────┬─────────────────┬──────────────┐
        │ Significance →  │ Treat / Diagnose  │ Drive Mgmt      │ Inform Mgmt  │
        ├─────────────────┼───────────────────┼─────────────────┼──────────────┤
        │ Critical        │ Category IV       │ Category III    │ Category II  │
        │ Serious         │ Category III      │ Category II     │ Category II  │
        │ Non-Serious     │ Category II       │ Category I      │ Category I   │
        └─────────────────┴───────────────────┴─────────────────┴──────────────┘
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class HealthcareState(Enum):
    """
    IMDRF N12: State of healthcare situation/condition.
    Reflects the urgency/severity of the patient's medical context.
    """
    CRITICAL    = "critical"    # Life-threatening / irreversible
    SERIOUS     = "serious"     # Long-term harm, hospitalization likely
    NON_SERIOUS = "non_serious" # Temporary, no lasting harm expected


class SignificanceOfOutput(Enum):
    """
    IMDRF N12: Significance of SaMD information/output to healthcare decision.
    Reflects how directly the SaMD output drives clinical action.
    """
    TREAT_OR_DIAGNOSE = "treat_or_diagnose"  # Output IS the treatment/diagnosis decision
    DRIVE_MANAGEMENT  = "drive_management"   # Output determines next clinical step
    INFORM_MANAGEMENT = "inform_management"  # Output informs; clinician decides independently


# IMDRF Category Matrix (N12 Table 1)
_IMDRF_MATRIX = {
    (HealthcareState.CRITICAL,    SignificanceOfOutput.TREAT_OR_DIAGNOSE): 4,
    (HealthcareState.CRITICAL,    SignificanceOfOutput.DRIVE_MANAGEMENT):  3,
    (HealthcareState.CRITICAL,    SignificanceOfOutput.INFORM_MANAGEMENT): 2,
    (HealthcareState.SERIOUS,     SignificanceOfOutput.TREAT_OR_DIAGNOSE): 3,
    (HealthcareState.SERIOUS,     SignificanceOfOutput.DRIVE_MANAGEMENT):  2,
    (HealthcareState.SERIOUS,     SignificanceOfOutput.INFORM_MANAGEMENT): 2,
    (HealthcareState.NON_SERIOUS, SignificanceOfOutput.TREAT_OR_DIAGNOSE): 2,
    (HealthcareState.NON_SERIOUS, SignificanceOfOutput.DRIVE_MANAGEMENT):  1,
    (HealthcareState.NON_SERIOUS, SignificanceOfOutput.INFORM_MANAGEMENT): 1,
}


# FDA device class approximation from IMDRF category
_IMDRF_TO_FDA_CLASS = {
    1: "Class I",
    2: "Class I / Class II",
    3: "Class II / Class III",
    4: "Class III",
}

_RISK_LABELS = {
    1: "Low Risk",
    2: "Moderate Risk",
    3: "Moderate-High Risk",
    4: "High Risk",
}


@dataclass
class IMDRFCategoryResult:
    """Result of IMDRF risk categorization."""
    category: int
    healthcare_state: HealthcareState
    significance: SignificanceOfOutput
    risk_label: str
    fda_class_equivalent: str
    description: str
    clinical_evaluation_required: bool
    analytical_validation_required: bool
    clinical_validation_required: bool

    def __str__(self) -> str:
        return (
            f"IMDRF Category {self.category} ({self.risk_label})\n"
            f"  Healthcare State:    {self.healthcare_state.value}\n"
            f"  Output Significance: {self.significance.value}\n"
            f"  FDA Class Equiv.:    {self.fda_class_equivalent}\n"
            f"  Clinical Eval:       {'Required' if self.clinical_evaluation_required else 'May not be required'}\n"
        )


class IMDRFCategorizer:
    """
    Categorizes a SaMD per IMDRF N12 risk framework.

    Real-world examples by category:
        Category I:
            - Fitbit sleep tracking app (non-serious / inform)
            - Calorie counter / nutrition logger
            - Hospital inventory management

        Category II:
            - Blood pressure trending app for hypertension management
            - Philips IntelliSpace PACS viewer (inform / serious)
            - Symptom checker chatbot (inform / non-serious)

        Category III:
            - iRhythm Zio AT — AI ECG arrhythmia detection (drive / serious)
            - Dario CGM companion app (drive / serious)
            - Viz.ai stroke LVO detection (drive / critical)

        Category IV:
            - Medtronic CareLink closed-loop insulin (treat / critical)
            - Abbott FreeStyle Libre AID system (treat / critical)
            - Autonomous radiation therapy planning SaMD (treat / critical)
    """

    def categorize(
        self,
        healthcare_state: HealthcareState,
        significance: SignificanceOfOutput,
    ) -> IMDRFCategoryResult:
        """
        Determine IMDRF category.

        Args:
            healthcare_state: Severity of the patient's underlying condition
            significance: How directly the SaMD output drives clinical action

        Returns:
            IMDRFCategoryResult with category, risk label, and validation requirements
        """
        category = _IMDRF_MATRIX[(healthcare_state, significance)]

        # Per IMDRF N23: validation requirements by category
        return IMDRFCategoryResult(
            category=category,
            healthcare_state=healthcare_state,
            significance=significance,
            risk_label=_RISK_LABELS[category],
            fda_class_equivalent=_IMDRF_TO_FDA_CLASS[category],
            description=self._describe(category, healthcare_state, significance),
            clinical_evaluation_required=category >= 3,
            analytical_validation_required=category >= 2,
            clinical_validation_required=category >= 3,
        )

    def _describe(self, cat: int, state: HealthcareState, sig: SignificanceOfOutput) -> str:
        descriptions = {
            1: (
                f"Category I: Low risk SaMD. Output informs or drives management of "
                f"non-serious conditions. Analytical validation required. "
                f"Clinical evaluation may be achieved through analytical validation alone."
            ),
            2: (
                f"Category II: Moderate risk SaMD. Multiple pathways: "
                f"({'treat/diagnose for non-serious' if state == HealthcareState.NON_SERIOUS else 'inform/drive for serious/critical'}). "
                f"Analytical validation AND some clinical evidence required. "
                f"Equivalent to FDA Class I/II — 510(k) may be required."
            ),
            3: (
                f"Category III: Moderate-high risk SaMD. SaMD drives clinical management "
                f"of serious/critical conditions, OR treats/diagnoses serious conditions. "
                f"Full clinical validation required. FDA Class II/III pathway. "
                f"Clinical studies demonstrating safety and effectiveness expected."
            ),
            4: (
                f"Category IV: High risk SaMD. SaMD treats or diagnoses life-threatening "
                f"or critical conditions. Comprehensive clinical validation required. "
                f"Equivalent to FDA Class III — PMA typically required. "
                f"Highest level of evidence expected (RCT preferred)."
            ),
        }
        return descriptions[cat]

    def categorize_from_description(
        self,
        intended_use: str,
        is_autonomous: bool = False,
        condition_severity: str = "serious",
    ) -> IMDRFCategoryResult:
        """
        Helper to categorize from a textual intended use description.
        Uses simple heuristics — for demonstration purposes.
        """
        # Map condition severity
        state_map = {
            "critical": HealthcareState.CRITICAL,
            "life-threatening": HealthcareState.CRITICAL,
            "serious": HealthcareState.SERIOUS,
            "chronic": HealthcareState.SERIOUS,
            "non-serious": HealthcareState.NON_SERIOUS,
            "wellness": HealthcareState.NON_SERIOUS,
        }
        state = state_map.get(condition_severity.lower(), HealthcareState.SERIOUS)

        # Determine significance from keywords in intended use
        treat_keywords = ["treat", "deliver", "dose", "administer", "close-loop", "autonomous"]
        drive_keywords = ["diagnose", "detect", "identify", "alert", "recommend", "triage"]

        use_lower = intended_use.lower()
        if is_autonomous or any(k in use_lower for k in treat_keywords):
            sig = SignificanceOfOutput.TREAT_OR_DIAGNOSE
        elif any(k in use_lower for k in drive_keywords):
            sig = SignificanceOfOutput.DRIVE_MANAGEMENT
        else:
            sig = SignificanceOfOutput.INFORM_MANAGEMENT

        return self.categorize(state, sig)
