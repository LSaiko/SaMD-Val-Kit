"""
examples/class_iii_closed_loop_insulin.py
==========================================
Example: Class III SaMD — Closed-Loop Automated Insulin Delivery (AID) System

Real-world analogues:
    - Abbott FreeStyle Libre 3 with mylife CamAPS FX (CE marked)
    - Medtronic MiniMed 780G (FDA cleared 2023)
    - Insulet Omnipod 5 (FDA cleared 2022)
    - Tandem Control-IQ (FDA cleared 2019 — first FDA-cleared AID algorithm)

Regulatory pathway: PMA (Premarket Approval) — Class III highest risk
IEC 62304: Software Safety Class C (death possible from overdose/underdose)
IMDRF: Category IV (treat / critical condition)

Key risks for AID systems:
    - Hypoglycemia from insulin overdose (life-threatening)
    - Hyperglycemia / DKA from underdose
    - CGM sensor failure propagating to incorrect dosing
    - Cybersecurity attack on insulin delivery commands
    - AI algorithm failure on unseen patient physiology
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from samd_toolkit.core import SaMDDevice, DeviceClass, SoftwareSafetyClass, RegulatoryPathway
from samd_toolkit.validators.iq_oq_pq import IQOQPQGenerator
from samd_toolkit.standards.iso14971 import RiskManagementFile, RiskItem
from samd_toolkit.standards.iec62304 import IEC62304LifecycleValidator
from samd_toolkit.standards.imdrf import IMDRFCategorizer, HealthcareState, SignificanceOfOutput
from samd_toolkit.cybersecurity.fda_cyber import FDACybersecurityChecker
from samd_toolkit.cybersecurity.sbom import SBOMGenerator


def run_class_iii_example():
    print("\n" + "█"*70)
    print("  CLASS III SaMD VALIDATION EXAMPLE")
    print("  Closed-Loop Automated Insulin Delivery (AID) System")
    print("  Regulatory Pathway: PMA | IEC 62304 Class C | IMDRF Category IV")
    print("█"*70)

    # ---------------------------------------------------------------
    # 1. Define the Device
    # ---------------------------------------------------------------
    device = SaMDDevice(
        name="InsulinAI Closed-Loop Controller",
        version="1.0.0",
        manufacturer="DiabetesTech Inc.",
        device_class=DeviceClass.CLASS_III,
        software_safety_class=SoftwareSafetyClass.CLASS_C,
        regulatory_pathway=RegulatoryPathway.PMA,
        intended_use=(
            "Closed-loop automated insulin delivery for adults with Type 1 Diabetes Mellitus. "
            "The system receives continuous glucose sensor data and autonomously calculates "
            "and commands insulin pump delivery rates without clinician intervention."
        ),
        indications_for_use=(
            "For use in adults aged 18+ with T1DM who require insulin therapy. "
            "Intended for use with compatible CGM sensors and insulin pumps."
        ),
        contraindications=(
            "Not indicated for: Type 2 DM, pediatric patients (<18y), "
            "pregnancy, or use without compatible CGM/pump hardware."
        ),
        intended_users=["Patient", "Caregiver"],
        programming_language="C++ (embedded) / Python (cloud analytics)",
        operating_system="FreeRTOS (embedded) / Linux (cloud)",
        deployment_environment="Embedded + Cloud Hybrid",
        interfaces=["Bluetooth LE", "REST API", "CGM Data Stream", "Insulin Pump Protocol"],
        network_connected=True,
        contains_ai_ml=True,
        processes_phi=True,
        interoperates_with_ehr=True,
        predicate_device="Tandem Control-IQ (P180008/S001)",
    )

    print("\n[1] DEVICE PROFILE")
    print("-" * 50)
    for k, v in device.summary().items():
        print(f"  {k:<35} {v}")

    # ---------------------------------------------------------------
    # 2. IMDRF Risk Categorization
    # ---------------------------------------------------------------
    print("\n[2] IMDRF RISK CATEGORIZATION (N12)")
    print("-" * 50)
    categorizer = IMDRFCategorizer()
    imdrf_result = categorizer.categorize(
        healthcare_state=HealthcareState.CRITICAL,
        significance=SignificanceOfOutput.TREAT_OR_DIAGNOSE,
    )
    print(imdrf_result)
    print(f"  Description: {imdrf_result.description[:120]}...")
    print(f"  Clinical Validation Required:   {'YES — PMA-level evidence required' if imdrf_result.clinical_validation_required else 'No'}")

    # ---------------------------------------------------------------
    # 3. IEC 62304 Lifecycle Checklist
    # ---------------------------------------------------------------
    print("\n[3] IEC 62304 LIFECYCLE COMPLIANCE")
    print("-" * 50)
    lifecycle = IEC62304LifecycleValidator(device)
    required_activities = lifecycle.required_activities()
    print(f"  Safety Class C requires {len(required_activities)} lifecycle activities:")
    deliverables = lifecycle.deliverables_list()
    print(f"  Required Deliverables ({len(deliverables)}):")
    for i, d in enumerate(deliverables, 1):
        print(f"    {i:2}. {d}")

    # ---------------------------------------------------------------
    # 4. ISO 14971 Risk Management
    # ---------------------------------------------------------------
    print("\n[4] ISO 14971:2019 RISK MANAGEMENT FILE")
    print("-" * 50)
    rmf = RiskManagementFile(device)

    # Add AID-specific risks beyond the defaults
    rmf.add_risk(RiskItem(
        hazard="Insulin stack / overdose due to connectivity loss during delivery",
        hazardous_situation="Pump continues delivering insulin after BLE disconnect without cancel command",
        harm="Severe hypoglycemia, seizure, loss of consciousness, death",
        probability_before=2, severity=5,
        risk_controls=[
            "Pump firmware: autonomous cancel delivery after 30-second connectivity loss",
            "Hard-wired maximum total daily dose limit in pump hardware",
            "CGM-triggered local hypoglycemia suspend on pump (independent of controller)"
        ],
        control_type="Inherent Safety",
        probability_after=1,
        residual_risk_justification=(
            "Multiple independent layers: pump autonomy, hardware limits, CGM suspend. "
            "Residual risk ALARP; benefit of glycemic control outweighs residual risk."
        ),
        verification_method="Fault injection: simulate BLE loss during delivery; verify pump suspend",
    ))

    rmf.add_risk(RiskItem(
        hazard="CGM sensor drift leading to incorrect insulin dose calculation",
        hazardous_situation="Algorithm receives incorrect high glucose reading, commands excess insulin",
        harm="Severe hypoglycemia",
        probability_before=3, severity=5,
        risk_controls=[
            "CGM signal plausibility check: rate-of-change limits (>4 mg/dL/min → suspend and alert)",
            "Require calibration confirmation if CGM delta exceeds physiological plausibility",
            "Maximum single-command dose hard limit regardless of glucose reading"
        ],
        control_type="Inherent Safety + Protective Measure",
        probability_after=1,
        residual_risk_justification="Plausibility checking catches sensor drift; hardware limits backstop algorithm",
        verification_method="CGM fault injection testing; sensitivity analysis in clinical validation",
    ))

    rmf.print_summary()

    # ---------------------------------------------------------------
    # 5. IQ/OQ/PQ Protocol Generation
    # ---------------------------------------------------------------
    print("\n[5] IQ/OQ/PQ VALIDATION PROTOCOL")
    print("-" * 50)
    generator = IQOQPQGenerator(device)
    session = generator.generate_full_package(
        prepared_by="Jane Smith, QE",
        site="DiabetesTech Inc. — Boston, MA",
    )
    counts = generator.item_count_by_protocol()
    print(f"  Generated validation protocol:")
    for k, v in counts.items():
        print(f"    {k}: {v} items")
    print(f"\n  Session ID: {session.session_id}")
    print(f"  Device:     {session.device.name} v{session.device.version}")
    print(f"  Protocol:   {session.protocol_type}")

    # Show sample items
    print("\n  Sample IQ Items:")
    for item in session.get_by_section("Security Baseline")[:1]:
        print(f"    [{item.item_id}] {item.requirement[:70]}...")
        print(f"    Reference: {item.reference_standard}")

    print("\n  Sample OQ Items:")
    for item in session.get_by_section("AI/ML Model Validation")[:1]:
        print(f"    [{item.item_id}] {item.requirement[:70]}...")
        print(f"    Reference: {item.reference_standard}")

    print("\n  Sample PQ Items:")
    for item in session.get_by_section("Clinical Scenarios")[:1]:
        print(f"    [{item.item_id}] {item.requirement[:70]}...")
        print(f"    Reference: {item.reference_standard}")

    # ---------------------------------------------------------------
    # 6. Cybersecurity Checklist
    # ---------------------------------------------------------------
    print("\n[6] FDA 2023 CYBERSECURITY CHECKLIST")
    print("-" * 50)
    sbom = SBOMGenerator(device).generate()
    sbom.print_summary()

    cyber = FDACybersecurityChecker(device, sbom)
    cyber.print_summary()

    # ---------------------------------------------------------------
    # 7. PMA Submission Package Summary
    # ---------------------------------------------------------------
    print("\n[7] PMA PREMARKET APPROVAL PACKAGE CHECKLIST")
    print("-" * 50)
    pma_sections = [
        ("Cover Sheet & Table of Contents",           "21 CFR 814.20(a)"),
        ("Indications for Use Statement",              "21 CFR 814.20(b)(3)"),
        ("Device Description (hardware + software)",  "21 CFR 814.20(b)(4)"),
        ("Substantial Equivalence (if De Novo)",      "N/A — PMA pathway"),
        ("Software Documentation Package",             "FDA SaMD Guidance; IEC 62304"),
        ("Risk Management File (ISO 14971)",           "ISO 14971:2019"),
        ("Cybersecurity Documentation (SBOM + CVD)", "FD&C §524B; FDA Cyber 2023"),
        ("Bench/Analytical Performance Testing",      "FDA SaMD Guidance §V.A"),
        ("Clinical Study Data (IDE Study)",            "21 CFR 812; FDA SaMD §V.B"),
        ("Labeling (IFU + Cybersecurity Label)",      "21 CFR 801; FDA Cyber 2023 §VII"),
        ("Manufacturing Information",                  "21 CFR 814.20(b)(10)"),
        ("Post-Approval Study Plan",                   "21 CFR 814.82"),
    ]
    for section, ref in pma_sections:
        print(f"  ☐ {section:<50} [{ref}]")

    print("\n" + "="*70)
    print("  Class III validation framework generated successfully.")
    print("  This package supports a PMA submission under 21 CFR Part 814.")
    print("="*70 + "\n")


if __name__ == "__main__":
    run_class_iii_example()
