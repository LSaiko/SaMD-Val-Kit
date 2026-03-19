"""
examples/class_ii_ecg_monitor.py
===================================
Example: Class II SaMD — AI-Driven ECG Arrhythmia Detection

Real-world analogues:
    - iRhythm Zio AT (K192613) — FDA 510(k) cleared; AI-driven extended Holter
    - AliveCor KardiaMobile 6L (K200010) — AI ECG, 6-lead
    - Apple Watch ECG (K182074) — Atrial fibrillation detection
    - Cardiologs Platform — AI ECG analysis for hospital-grade Holter

Regulatory pathway: 510(k) — Class II, Special Controls
IEC 62304: Software Safety Class B (non-serious injury from false negative)
IMDRF: Category III (drive management / serious condition)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from samd_toolkit.core import SaMDDevice, DeviceClass, SoftwareSafetyClass, RegulatoryPathway
from samd_toolkit.validators.iq_oq_pq import IQOQPQGenerator
from samd_toolkit.standards.iso14971 import RiskManagementFile
from samd_toolkit.standards.iec62304 import IEC62304LifecycleValidator, SoftwareSafetyClass as IECSafetyClass
from samd_toolkit.standards.imdrf import IMDRFCategorizer, HealthcareState, SignificanceOfOutput
from samd_toolkit.cybersecurity.fda_cyber import FDACybersecurityChecker
from samd_toolkit.cybersecurity.sbom import SBOMGenerator


def run_class_ii_example():
    print("\n" + "█"*70)
    print("  CLASS II SaMD VALIDATION EXAMPLE")
    print("  AI-Driven ECG Arrhythmia Detection (CardioWatch AI)")
    print("  Regulatory Pathway: 510(k) | IEC 62304 Class B | IMDRF Category III")
    print("█"*70)

    device = SaMDDevice(
        name="CardioWatch AI",
        version="2.1.0",
        manufacturer="MedTech Corp.",
        device_class=DeviceClass.CLASS_II,
        software_safety_class=SoftwareSafetyClass.CLASS_B,
        regulatory_pathway=RegulatoryPathway.K510,
        intended_use=(
            "AI-powered analysis of single-lead ECG recordings for detection of "
            "atrial fibrillation (AF), other arrhythmias, and normal sinus rhythm. "
            "Results are intended to aid physician interpretation; physician review "
            "is required before clinical decisions."
        ),
        predicate_device="iRhythm Zio AT (K192613)",
        product_code="MQP",
        intended_users=["HCP", "Cardiologist"],
        programming_language="Python",
        operating_system="Linux (AWS)",
        deployment_environment="Cloud (SaaS)",
        interfaces=["REST API", "DICOM", "HL7 FHIR R4", "Web Portal"],
        network_connected=True,
        contains_ai_ml=True,
        processes_phi=True,
        interoperates_with_ehr=True,
    )

    print("\n[1] DEVICE PROFILE")
    print("-" * 50)
    for k, v in device.summary().items():
        print(f"  {k:<35} {v}")

    # IMDRF
    print("\n[2] IMDRF RISK CATEGORIZATION")
    print("-" * 50)
    cat = IMDRFCategorizer().categorize(
        HealthcareState.SERIOUS,
        SignificanceOfOutput.DRIVE_MANAGEMENT,
    )
    print(cat)

    # IEC 62304
    print("\n[3] IEC 62304 — CLASS B REQUIREMENTS")
    print("-" * 50)
    lifecycle = IEC62304LifecycleValidator(device)
    required = lifecycle.required_activities()
    print(f"  Safety Class B: {len(required)} activities required")
    print("  Key differences from Class A (additional Class B requirements):")
    class_b_only = [a for a in required if "A" not in a.required_for_class]
    for act in class_b_only:
        print(f"    + §{act.section}: {act.activity}")
    print(f"\n  Required Deliverables:")
    for d in lifecycle.deliverables_list():
        print(f"    - {d}")

    # IQ/OQ/PQ
    print("\n[4] IQ/OQ/PQ PROTOCOL SUMMARY")
    print("-" * 50)
    gen = IQOQPQGenerator(device)
    session = gen.generate_full_package(prepared_by="Alice Chen, RA", site="MedTech Corp. — San Jose, CA")
    counts = gen.item_count_by_protocol()
    for k, v in counts.items():
        print(f"    {k}: {v} items")

    # Risk Management
    print("\n[5] ISO 14971 RISK SUMMARY")
    print("-" * 50)
    rmf = RiskManagementFile(device)
    rmf.print_summary()

    # SBOM + Cybersecurity
    print("\n[6] SBOM + CYBERSECURITY")
    print("-" * 50)
    sbom = SBOMGenerator(device).generate()
    print(f"  SBOM Components: {len(sbom.components)}")
    cyber = FDACybersecurityChecker(device, sbom)
    mandatory = cyber.mandatory_524b_controls
    print(f"  FDA §524B Mandatory Controls: {len(mandatory)}")
    print(f"  (All mandatory for 510(k) submissions after March 29, 2023)")

    # 510(k) Submission Checklist
    print("\n[7] 510(k) SUBMISSION PACKAGE CHECKLIST")
    print("-" * 50)
    k510_sections = [
        ("Cover Sheet (FDA Form 3514)",              "21 CFR 807.87(a)"),
        ("Table of Contents",                        "21 CFR 807.87"),
        ("Indications for Use (FDA Form 3881)",      "21 CFR 807.87(b)"),
        ("510(k) Summary or Statement",              "21 CFR 807.92/807.93"),
        ("Truthful and Accuracy Statement",          "21 CFR 807.87(k)"),
        ("Class III Summary and Certification",      "21 CFR 807.87(l)"),
        ("Device Description",                       "21 CFR 807.87(c)"),
        ("Substantial Equivalence Discussion",       "21 CFR 807.87(f)"),
        ("Performance Standards",                    "21 CFR 807.87(j)"),
        ("Software Documentation (Level of Concern)","FDA Guidance 2019"),
        ("AI/ML Algorithm Description",              "FDA AI/ML Action Plan 2021"),
        ("Cybersecurity Documentation + SBOM",       "FD&C §524B; FDA Cyber 2023"),
        ("Biocompatibility (if applicable)",         "ISO 10993"),
        ("Labeling",                                 "21 CFR 801"),
        ("Human Factors / Usability Testing",        "IEC 62366-1; FDA HF Guidance"),
        ("Clinical/Performance Data",                "FDA SaMD Guidance §V"),
    ]
    for section, ref in k510_sections:
        print(f"  ☐ {section:<50} [{ref}]")

    print("\n" + "="*70)
    print("  Class II 510(k) validation framework generated successfully.")
    print("="*70 + "\n")


if __name__ == "__main__":
    run_class_ii_example()
