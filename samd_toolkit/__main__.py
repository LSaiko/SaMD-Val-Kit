"""
samd_toolkit/__main__.py
==========================
CLI entry point for the SaMD Validation Toolkit.

Usage:
    python -m samd_toolkit
    python -m samd_toolkit demo --class II
    python -m samd_toolkit demo --class III
"""

import sys
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="SaMD Validation Toolkit — IQ/OQ/PQ Generator & Checklist Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Run Class I wellness app demo:
    python -m samd_toolkit demo --class I

  Run Class II ECG monitor demo:
    python -m samd_toolkit demo --class II

  Run Class III closed-loop insulin demo:
    python -m samd_toolkit demo --class III

  Run all demos:
    python -m samd_toolkit demo --class all
        """
    )

    parser.add_argument(
        "command",
        choices=["demo", "version", "standards"],
        help="Command to run"
    )
    parser.add_argument(
        "--class",
        dest="device_class",
        choices=["I", "II", "III", "all"],
        default="all",
        help="FDA device class for demo"
    )

    args = parser.parse_args()

    if args.command == "version":
        print("SaMD Validation Toolkit v0.1.0")
        print("Standards: FDA 21 CFR 820/11 | IEC 62304 | ISO 14971 | IMDRF | EU MDR")
        print("Cybersecurity: FDA 2023 | IEC 62443 | FD&C §524B")
        return

    if args.command == "standards":
        print_standards_reference()
        return

    if args.command == "demo":
        run_demos(args.device_class)


def run_demos(device_class: str):
    if device_class in ("I", "all"):
        from examples.class_i_wellness_app import run_class_i_example
        run_class_i_example()

    if device_class in ("II", "all"):
        from examples.class_ii_ecg_monitor import run_class_ii_example
        run_class_ii_example()

    if device_class in ("III", "all"):
        from examples.class_iii_closed_loop_insulin import run_class_iii_example
        run_class_iii_example()


def print_standards_reference():
    standards = [
        ("UNITED STATES (FDA)", ""),
        ("21 CFR Part 820",      "Quality System Regulation (QSR)"),
        ("21 CFR Part 11",       "Electronic Records & Electronic Signatures"),
        ("21 CFR Part 803",      "Medical Device Reporting (MDR)"),
        ("FD&C Act §524B",       "Cybersecurity for Cyber Devices (2023)"),
        ("FDA SaMD Guidance",    "Software as a Medical Device — Clinical Evaluation (2017)"),
        ("FDA CDS Guidance",     "Clinical Decision Support Software (2022)"),
        ("FDA AI/ML Plan",       "Action Plan for AI/ML-Based SaMD (2021)"),
        ("FDA Cyber 2023",       "Cybersecurity in Medical Devices: Premarket Submissions"),
        ("",                     ""),
        ("INTERNATIONAL",        ""),
        ("IEC 62304:2015",       "Medical Device Software — Software Lifecycle Processes"),
        ("IEC 62443",            "Industrial Cybersecurity (adopted for SaMD)"),
        ("ISO 14971:2019",       "Risk Management for Medical Devices"),
        ("ISO 13485:2016",       "Quality Management Systems for Medical Devices"),
        ("IEC 82304-1",          "Health Software — General Requirements for Safety"),
        ("IEC 62366-1:2015",     "Usability Engineering for Medical Devices"),
        ("IMDRF N10/N12/N23",   "SaMD Framework, Risk Categorization, Clinical Evaluation"),
        ("EU MDR 2017/745",      "European Medical Device Regulation"),
        ("ANSI/AAMI HE75",      "Human Factors Engineering for Medical Devices"),
    ]
    print("\nRegulatory Standards Reference")
    print("="*60)
    for std, desc in standards:
        if not std:
            print()
        elif not desc:
            print(f"\n  {std}")
            print("  " + "-"*40)
        else:
            print(f"  {std:<25} {desc}")
    print()


if __name__ == "__main__":
    main()
