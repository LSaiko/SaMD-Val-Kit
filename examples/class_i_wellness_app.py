"""
examples/class_i_wellness_app.py
===================================
Example: Class I SaMD — Wellness / General Wellness App

Real-world analogues:
    - Fitbit / Garmin activity tracking (non-clinical output)
    - Apple Health app (aggregation; non-diagnostic)
    - MyFitnessPal / calorie tracking
    - Mental wellness apps (Calm, Headspace) — FDA issued guidance
    - Hospital patient scheduling/administrative software

NOTE: Not all wellness apps are SaMD. FDA's "General Wellness: Policy for
Low Risk Devices" guidance (2016) provides safe harbor for wellness software
that poses a low risk to users and is not intended to diagnose, treat, or
prevent a specific disease.

Regulatory: Exempt from 510(k) (most Class I)
IEC 62304: Software Safety Class A (no injury possible from software failure)
IMDRF: Category I (inform / non-serious)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from samd_toolkit.core import SaMDDevice, DeviceClass, SoftwareSafetyClass, RegulatoryPathway
from samd_toolkit.validators.iq_oq_pq import IQOQPQGenerator
from samd_toolkit.standards.iso14971 import RiskManagementFile
from samd_toolkit.standards.iec62304 import IEC62304LifecycleValidator
from samd_toolkit.standards.imdrf import IMDRFCategorizer, HealthcareState, SignificanceOfOutput
from samd_toolkit.cybersecurity.sbom import SBOMGenerator


def run_class_i_example():
    print("\n" + "█"*70)
    print("  CLASS I SaMD VALIDATION EXAMPLE")
    print("  General Wellness Activity Tracking App (WellTrack)")
    print("  Regulatory: Exempt | IEC 62304 Class A | IMDRF Category I")
    print("█"*70)

    device = SaMDDevice(
        name="WellTrack Activity Monitor",
        version="3.2.1",
        manufacturer="HealthSoft Inc.",
        device_class=DeviceClass.CLASS_I,
        software_safety_class=SoftwareSafetyClass.CLASS_A,
        regulatory_pathway=RegulatoryPathway.EXEMPT,
        intended_use=(
            "General wellness application for tracking physical activity, sleep patterns, "
            "and daily step count. Provides motivational feedback and wellness tips. "
            "Not intended to diagnose, treat, cure, or prevent any disease or condition."
        ),
        intended_users=["Patient", "Consumer"],
        programming_language="Swift / Kotlin",
        operating_system="iOS 16+ / Android 13+",
        deployment_environment="Mobile App + Cloud",
        interfaces=["REST API", "Apple HealthKit", "Google Fit"],
        network_connected=True,
        contains_ai_ml=False,
        processes_phi=False,       # General wellness data, not clinical PHI
        interoperates_with_ehr=False,
    )

    print("\n[1] DEVICE PROFILE")
    print("-" * 50)
    for k, v in device.summary().items():
        print(f"  {k:<35} {v}")

    # IMDRF
    print("\n[2] IMDRF RISK CATEGORIZATION")
    print("-" * 50)
    cat = IMDRFCategorizer().categorize(
        HealthcareState.NON_SERIOUS,
        SignificanceOfOutput.INFORM_MANAGEMENT,
    )
    print(cat)

    # IEC 62304 Class A — minimal requirements
    print("\n[3] IEC 62304 CLASS A — MINIMUM REQUIREMENTS")
    print("-" * 50)
    lifecycle = IEC62304LifecycleValidator(device)
    required = lifecycle.required_activities()
    print(f"  Safety Class A: Only {len(required)} activities required")
    print("  (Class A has significantly reduced documentation requirements)")
    print("\n  Required activities for Class A:")
    for act in required:
        print(f"    §{act.section}: {act.activity}")
        print(f"      Deliverable: {act.deliverable}")
    print("\n  NOTE: Class A does NOT require:")
    print("    - Software Architecture Document")
    print("    - Detailed Design Specification")
    print("    - Unit Testing")
    print("    - Software Risk Analysis (ISO 14971 still recommended)")
    print("    - Software Integration Testing")

    # IQ/OQ/PQ (lightweight for Class I)
    print("\n[4] IQ/OQ/PQ PROTOCOL (Class I — Streamlined)")
    print("-" * 50)
    gen = IQOQPQGenerator(device)
    session = gen.generate_full_package(
        prepared_by="Bob Johnson, QE",
        site="HealthSoft Inc. — Austin, TX",
    )
    counts = gen.item_count_by_protocol()
    print("  Class I generates a streamlined protocol (fewer items than Class II/III):")
    for k, v in counts.items():
        print(f"    {k}: {v} items")
    print("\n  Key difference: No electronic signature (21 CFR Part 11) items,")
    print("  no audit trail requirements, no closed-loop safety tests.")

    # Risk Management (Class I — simplified)
    print("\n[5] ISO 14971 RISK SUMMARY (Class I)")
    print("-" * 50)
    rmf = RiskManagementFile(device)
    rmf.print_summary()
    print("  Note: Class I risks are generally low severity.")
    print("  Primary residual risks: incorrect activity data → minor behavior change.")

    # SBOM
    print("\n[6] SBOM (FDA §524B applies if network-connected)")
    print("-" * 50)
    sbom = SBOMGenerator(device).generate()
    print(f"  Total components: {len(sbom.components)}")
    print("  Note: Even Class I SaMD requires SBOM if it is a 'cyber device'")
    print("  (contains software + connects to internet) per FD&C §524B (2023).")
    sbom.print_summary()

    # Regulatory pathway summary
    print("\n[7] REGULATORY SUBMISSION SUMMARY — CLASS I EXEMPT")
    print("-" * 50)
    print("  Class I Exempt devices do NOT require:")
    print("    ✗ 510(k) premarket notification")
    print("    ✗ PMA")
    print("    ✗ Design controls (21 CFR 820.30) — HOWEVER, best practice to apply")
    print()
    print("  Class I Exempt devices DO require:")
    print("    ✓ Establishment registration (21 CFR 807)")
    print("    ✓ Device listing (21 CFR 807)")
    print("    ✓ General controls (21 CFR 820)")
    print("    ✓ Labeling (21 CFR 801)")
    print("    ✓ MDR reporting if device causes/contributes to death/serious injury")
    print("    ✓ SBOM if network-connected (FD&C §524B)")
    print()
    print("  FDA General Wellness Safe Harbor (2016 guidance):")
    print("    → If the intended use is wellness and poses low risk,")
    print("       FDA may exercise enforcement discretion")
    print("    → Still good practice to maintain validation documentation")

    print("\n" + "="*70)
    print("  Class I validation framework generated successfully.")
    print("="*70 + "\n")


if __name__ == "__main__":
    run_class_i_example()
