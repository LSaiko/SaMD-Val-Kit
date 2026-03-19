"""
samd_toolkit/standards/iec62304.py
=====================================
IEC 62304:2006+AMD1:2015 — Medical Device Software Lifecycle Processes

IEC 62304 is the primary international standard for medical device software
development. It defines software safety classes and required lifecycle activities.

Software Safety Classes:
    Class A: No injury or damage to health possible from software failure
    Class B: Non-serious injury possible from software failure
    Class C: Death or serious injury possible from software failure

Key Principle: "You cannot validate your way to safety — safety must be
designed in." (IEC 62304 risk-based approach)

Real-world class assignments:
    Class A: Hospital inventory tracker, appointment scheduling, billing software
    Class B: Blood pressure monitoring app, ECG viewer (non-diagnostic),
             nurse call system, non-critical alarm management
    Class C: Closed-loop drug delivery, ventilator control, radiation dosing,
             implantable device programming, autonomous AI diagnostic (Class III)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Callable


class SoftwareSafetyClass(Enum):
    """IEC 62304 §4.3 — Software Safety Classification."""
    CLASS_A = "A"   # No injury possible
    CLASS_B = "B"   # Non-serious injury possible
    CLASS_C = "C"   # Death or serious injury possible


# Required process activities by safety class
# Per IEC 62304 Table 1 — Activities required per safety class
REQUIRED_ACTIVITIES: Dict[str, Dict[str, bool]] = {
    # Section: {class_a, class_b, class_c}
    "5.1 Software Development Planning":               {"A": True,  "B": True,  "C": True},
    "5.2 Software Requirements Analysis":              {"A": True,  "B": True,  "C": True},
    "5.3 Software Architectural Design":               {"A": False, "B": True,  "C": True},
    "5.4 Software Detailed Design":                    {"A": False, "B": False, "C": True},
    "5.5 Software Unit Implementation & Verification": {"A": False, "B": False, "C": True},
    "5.6 Software Integration & Integration Testing":  {"A": False, "B": True,  "C": True},
    "5.7 Software System Testing":                     {"A": True,  "B": True,  "C": True},
    "5.8 Software Release":                            {"A": True,  "B": True,  "C": True},
    "6.1 Software Maintenance Process":                {"A": True,  "B": True,  "C": True},
    "7.1 Software Risk Management":                    {"A": False, "B": True,  "C": True},
    "8.1 Software Configuration Management":           {"A": True,  "B": True,  "C": True},
    "8.2 Software Problem Resolution":                 {"A": True,  "B": True,  "C": True},
    "9.1 Software Safety Class Determination":         {"A": True,  "B": True,  "C": True},
}


@dataclass
class LifecycleActivity:
    """A single IEC 62304 lifecycle process activity."""
    section: str
    activity: str
    required_for_class: List[str]   # ["A", "B", "C"] or subset
    deliverable: str                 # Required document/artifact
    guidance: str = ""
    is_complete: bool = False
    evidence_ref: str = ""

    def is_required_for(self, safety_class: SoftwareSafetyClass) -> bool:
        return safety_class.value in self.required_for_class

    def to_dict(self) -> Dict:
        return {
            "Section": self.section,
            "Activity": self.activity,
            "Required For Classes": ", ".join(self.required_for_class),
            "Deliverable": self.deliverable,
            "Complete": "Yes" if self.is_complete else "No",
            "Evidence": self.evidence_ref,
        }


class IEC62304LifecycleValidator:
    """
    Validates software development lifecycle compliance with IEC 62304.

    Generates a gap analysis showing which activities are required
    for the device's software safety class and which are completed.
    """

    LIFECYCLE_ACTIVITIES: List[LifecycleActivity] = [

        # --- §5.1 Software Development Planning ---
        LifecycleActivity("5.1", "Software Development Plan",
            required_for_class=["A", "B", "C"],
            deliverable="Software Development Plan (SDP)",
            guidance="Must include software safety class determination, applicable standards, tools, lifecycle phases"),
        LifecycleActivity("5.1", "Software Safety Class Assignment",
            required_for_class=["A", "B", "C"],
            deliverable="Safety Class Justification Document",
            guidance="Document reasoning for class assignment; review when requirements change"),

        # --- §5.2 Software Requirements Analysis ---
        LifecycleActivity("5.2", "Software Requirements Specification",
            required_for_class=["A", "B", "C"],
            deliverable="Software Requirements Specification (SRS)",
            guidance="Functional, performance, interface, safety, and security requirements"),
        LifecycleActivity("5.2", "SOUP Software Requirements",
            required_for_class=["B", "C"],
            deliverable="SOUP List with functional/performance requirements",
            guidance="For each SOUP item: document required functionality, hardware/software constraints"),
        LifecycleActivity("5.2", "Risk Controls Traceability",
            required_for_class=["B", "C"],
            deliverable="Requirements Traceability Matrix (RTM) linking risks to requirements",
            guidance="Each risk control measure must trace to a specific software requirement"),

        # --- §5.3 Software Architecture Design ---
        LifecycleActivity("5.3", "Software Architecture Document",
            required_for_class=["B", "C"],
            deliverable="Software Architecture Document (SAD)",
            guidance="Component breakdown, interfaces, data flows, SOUP integration points"),
        LifecycleActivity("5.3", "Segregation of Safety-Critical Components",
            required_for_class=["C"],
            deliverable="Safety-Critical Component Identification in Architecture",
            guidance="Class C: safety-critical software items must be segregated from non-safety items"),

        # --- §5.4 Software Detailed Design ---
        LifecycleActivity("5.4", "Detailed Design Specification",
            required_for_class=["C"],
            deliverable="Software Detailed Design Specification (SDDS)",
            guidance="Unit-level design; interfaces; data structures; algorithms"),

        # --- §5.5 Software Unit Implementation & Verification ---
        LifecycleActivity("5.5", "Unit Implementation",
            required_for_class=["C"],
            deliverable="Implemented source code + code review records",
            guidance="Class C: formal code review/inspection required for safety-critical units"),
        LifecycleActivity("5.5", "Unit Verification",
            required_for_class=["C"],
            deliverable="Unit Test Plan and Unit Test Results",
            guidance="Class C: unit testing required; verify correct implementation of detailed design"),

        # --- §5.6 Software Integration & Integration Testing ---
        LifecycleActivity("5.6", "Integration Testing",
            required_for_class=["B", "C"],
            deliverable="Integration Test Plan and Results",
            guidance="Test software components together; verify interfaces and data flows"),
        LifecycleActivity("5.6", "SOUP Integration Verification",
            required_for_class=["B", "C"],
            deliverable="SOUP Verification Records",
            guidance="Verify each SOUP item functions correctly in integrated system"),

        # --- §5.7 Software System Testing ---
        LifecycleActivity("5.7", "System Test Plan",
            required_for_class=["A", "B", "C"],
            deliverable="System Test Plan covering all SRS requirements",
            guidance="Regression test, functional test, performance test, security test"),
        LifecycleActivity("5.7", "System Test Execution and Results",
            required_for_class=["A", "B", "C"],
            deliverable="System Test Report with pass/fail summary",
            guidance="All tests executed; deviations documented and dispositioned"),
        LifecycleActivity("5.7", "Traceability: Requirements to Tests",
            required_for_class=["A", "B", "C"],
            deliverable="Requirements ↔ Test Traceability Matrix",
            guidance="Each SRS requirement must be covered by at least one system test"),

        # --- §5.8 Software Release ---
        LifecycleActivity("5.8", "Software Release Package",
            required_for_class=["A", "B", "C"],
            deliverable="Software Release Record with approved version",
            guidance="Version identifier, release notes, known anomalies/SOUP list"),
        LifecycleActivity("5.8", "Known Anomalies Assessment",
            required_for_class=["A", "B", "C"],
            deliverable="Known Anomalies List with safety impact assessment",
            guidance="Document all open defects; assess safety impact; accept/defer with justification"),

        # --- §6 Software Maintenance ---
        LifecycleActivity("6.1", "Software Maintenance Plan",
            required_for_class=["A", "B", "C"],
            deliverable="Software Maintenance Plan",
            guidance="Process for post-release problem reports, modifications, and re-release"),
        LifecycleActivity("6.2", "Problem and Modification Process",
            required_for_class=["A", "B", "C"],
            deliverable="Problem Report and Change Request procedures",
            guidance="Evaluate impact of changes on safety class; re-run affected V&V activities"),

        # --- §7 Software Risk Management ---
        LifecycleActivity("7.1", "Software Risk Analysis",
            required_for_class=["B", "C"],
            deliverable="Software Hazard Analysis integrated with ISO 14971 RMF",
            guidance="FMEA/SFMEA for software failure modes; link to Risk Management File"),
        LifecycleActivity("7.1", "Risk Control Verification",
            required_for_class=["B", "C"],
            deliverable="Evidence that software risk controls are implemented and effective",
            guidance="Each software risk control must be verified; traceability to test evidence required"),

        # --- §8 Software Configuration Management ---
        LifecycleActivity("8.1", "Configuration Management Plan",
            required_for_class=["A", "B", "C"],
            deliverable="Software Configuration Management Plan (SCMP)",
            guidance="Version control, baseline management, change control, build procedures"),
        LifecycleActivity("8.1", "SOUP Identification and Management",
            required_for_class=["A", "B", "C"],
            deliverable="SOUP List with versions, manufacturer, and justification",
            guidance="All third-party components identified; Class C: anomaly list for each SOUP"),
        LifecycleActivity("8.2", "Problem Resolution Process",
            required_for_class=["A", "B", "C"],
            deliverable="Software Problem Report (SPR) procedure and records",
            guidance="Track problems from identification through resolution; safety impact evaluated"),
    ]

    def __init__(self, device):
        self.device = device
        self.safety_class = device.software_safety_class

    def required_activities(self) -> List[LifecycleActivity]:
        """Return activities required for this device's safety class."""
        return [a for a in self.LIFECYCLE_ACTIVITIES
                if a.is_required_for(self.safety_class)]

    def gap_analysis(self, completed_sections: List[str] = None) -> Dict:
        """
        Generate a gap analysis against IEC 62304 requirements.

        Args:
            completed_sections: List of section numbers completed (e.g., ["5.1", "5.2"])

        Returns:
            Dict with required, completed, and gaps
        """
        completed = set(completed_sections or [])
        required = self.required_activities()
        gaps = [a for a in required if a.section not in completed]
        done = [a for a in required if a.section in completed]

        return {
            "Device": self.device.name,
            "Safety Class": self.safety_class.value,
            "Total Required Activities": len(required),
            "Completed": len(done),
            "Gaps": len(gaps),
            "Compliance": f"{(len(done)/len(required)*100):.0f}%" if required else "100%",
            "Gap List": [f"{a.section}: {a.activity}" for a in gaps],
        }

    def print_checklist(self):
        """Print a formatted IEC 62304 compliance checklist."""
        required = self.required_activities()
        print("\n" + "="*70)
        print(f"IEC 62304:2006+AMD1:2015 COMPLIANCE CHECKLIST")
        print(f"Device: {self.device.name}  |  Safety Class: {self.safety_class.value}")
        print("="*70)
        current_section = ""
        for act in required:
            if act.section != current_section:
                print(f"\n  §{act.section}")
                current_section = act.section
            status = "☑" if act.is_complete else "☐"
            print(f"    {status} {act.activity}")
            print(f"      → Deliverable: {act.deliverable}")
        print()

    def deliverables_list(self) -> List[str]:
        """Return sorted list of all required deliverables."""
        return sorted(set(a.deliverable for a in self.required_activities()))
