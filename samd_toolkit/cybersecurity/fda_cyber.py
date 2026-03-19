"""
samd_toolkit/cybersecurity/fda_cyber.py
=========================================
FDA Cybersecurity Checklist for SaMD — Based on:

1. FDA "Cybersecurity in Medical Devices: Quality System Considerations and
   Content of Premarket Submissions" (2023) — Replaces 2014/2018 drafts
2. FDA "Postmarket Management of Cybersecurity in Medical Devices" (2016)
3. Section 524B of FD&C Act (added by Consolidated Appropriations Act, 2023)
   — Mandatory cybersecurity requirements for cyber devices submitted after
     March 29, 2023
4. IEC 62443-4-1: Secure product development lifecycle requirements
5. NIST Cybersecurity Framework (CSF) 2.0

Section 524B "Cyber Device" Definition:
    A device that (1) includes software, (2) is intended to connect to the
    internet, AND (3) contains technological characteristics that could be
    vulnerable to cybersecurity threats.

Key 2023 Guidance Requirements:
    - Software Bill of Materials (SBOM) — mandatory
    - Coordinated vulnerability disclosure policy
    - Post-market cybersecurity patching plan
    - Cybersecurity risk management throughout TPLC
    - Security by design
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional
from datetime import datetime


class CyberControlStatus(Enum):
    COMPLIANT     = "Compliant"
    NON_COMPLIANT = "Non-Compliant"
    PARTIAL       = "Partial"
    NOT_ASSESSED  = "Not Assessed"
    NOT_APPLICABLE = "N/A"


class CyberSeverity(Enum):
    """CVSS v3.1 severity categories."""
    CRITICAL = "Critical"   # CVSS 9.0-10.0
    HIGH     = "High"       # CVSS 7.0-8.9
    MEDIUM   = "Medium"     # CVSS 4.0-6.9
    LOW      = "Low"        # CVSS 0.1-3.9
    NONE     = "None"       # CVSS 0.0


@dataclass
class CyberCheckItem:
    """A single cybersecurity control check."""
    control_id: str
    domain: str
    title: str
    requirement: str
    guidance: str
    references: List[str] = field(default_factory=list)
    status: CyberControlStatus = CyberControlStatus.NOT_ASSESSED
    finding: str = ""
    recommendation: str = ""
    severity_if_missing: CyberSeverity = CyberSeverity.HIGH
    is_mandatory_524b: bool = False     # Required under FD&C Act §524B

    def to_dict(self) -> Dict:
        return {
            "Control ID": self.control_id,
            "Domain": self.domain,
            "Title": self.title,
            "Requirement": self.requirement,
            "Status": self.status.value,
            "Finding": self.finding,
            "Severity if Missing": self.severity_if_missing.value,
            "§524B Mandatory": "Yes" if self.is_mandatory_524b else "No",
            "References": "; ".join(self.references),
        }


class FDACybersecurityChecker:
    """
    Runs the FDA 2023 Cybersecurity premarket checklist against a SaMD device.

    Organized by the FDA guidance domains:
        1. Security Risk Management
        2. Security Architecture
        3. Cybersecurity Testing
        4. Transparency (SBOM, Disclosure)
        5. Post-Market / TPLC Considerations
    """

    def __init__(self, device, sbom=None):
        self.device = device
        self.sbom = sbom
        self.controls: List[CyberCheckItem] = []
        self._build_checklist()

    def _build_checklist(self):
        d = self.device

        # ---------------------------------------------------------------
        # DOMAIN 1: Security Risk Management
        # ---------------------------------------------------------------
        self._add(CyberCheckItem(
            control_id="CY-RM-001",
            domain="Security Risk Management",
            title="Cybersecurity Risk Management Process",
            requirement=(
                "A documented cybersecurity risk management process exists, integrated "
                "with the ISO 14971 risk management process throughout the TPLC."
            ),
            guidance=(
                "The cybersecurity risk management plan should identify the threat model, "
                "attack surfaces, vulnerabilities, exploitability, and resulting patient harms. "
                "Reference: MITRE ATT&CK for ICS/Medical."
            ),
            references=["FDA Cyber 2023 §IV.A", "IEC 62443-4-1 SM-7", "ISO 14971:2019 §4"],
            severity_if_missing=CyberSeverity.CRITICAL,
            is_mandatory_524b=True,
        ))

        self._add(CyberCheckItem(
            control_id="CY-RM-002",
            domain="Security Risk Management",
            title="Threat Modeling",
            requirement=(
                "A threat model (e.g., STRIDE, PASTA, or MITRE ATT&CK) has been conducted "
                "for all attack surfaces, data flows, and trust boundaries."
            ),
            guidance=(
                "Document assets to protect, entry points, threat actors, attack vectors. "
                "Include medical-specific threats: ransomware disrupting care delivery, "
                "manipulation of clinical data, DoS on life-critical functions."
            ),
            references=["FDA Cyber 2023 §IV.A.1", "MITRE ATT&CK", "IEC 62443-3-2"],
            severity_if_missing=CyberSeverity.HIGH,
            is_mandatory_524b=True,
        ))

        self._add(CyberCheckItem(
            control_id="CY-RM-003",
            domain="Security Risk Management",
            title="Cybersecurity Risk Traceability",
            requirement=(
                "Cybersecurity risks are traceable from threat → vulnerability → "
                "risk → control measure → verification test."
            ),
            guidance="Traceability matrix linking cybersecurity hazards to design controls and test evidence.",
            references=["FDA Cyber 2023 §IV.A", "IEC 62304 §5.5.1"],
            severity_if_missing=CyberSeverity.HIGH,
            is_mandatory_524b=False,
        ))

        # ---------------------------------------------------------------
        # DOMAIN 2: Security Architecture
        # ---------------------------------------------------------------
        self._add(CyberCheckItem(
            control_id="CY-AR-001",
            domain="Security Architecture",
            title="Authentication & Authorization",
            requirement=(
                "Strong authentication implemented; default credentials prohibited; "
                "role-based access control enforced; session management secure."
            ),
            guidance=(
                "MFA required for remote access. Password policy: ≥12 chars, complexity, "
                "no hardcoded credentials in code or config. Session timeout after inactivity. "
                "NIST SP 800-63B AAL2 minimum for clinical users."
            ),
            references=["FDA Cyber 2023 §IV.B.1", "NIST SP 800-63B", "IEC 62443-3-3 SR 1.1", "HIPAA 164.312(d)"],
            severity_if_missing=CyberSeverity.CRITICAL,
            is_mandatory_524b=True,
        ))

        self._add(CyberCheckItem(
            control_id="CY-AR-002",
            domain="Security Architecture",
            title="Cryptography",
            requirement=(
                "All PHI and sensitive clinical data encrypted at rest (AES-256) "
                "and in transit (TLS 1.3). FIPS 140-2/3 validated modules used."
            ),
            guidance=(
                "Avoid deprecated protocols: TLS 1.0/1.1, SSL, MD5, SHA-1, DES. "
                "Cryptographic key management plan required. "
                "For medical imaging: consider DICOM TLS."
            ),
            references=["FDA Cyber 2023 §IV.B.2", "FIPS 140-3", "NIST SP 800-111", "HIPAA 164.312(e)(2)"],
            severity_if_missing=CyberSeverity.CRITICAL,
            is_mandatory_524b=True,
        ))

        self._add(CyberCheckItem(
            control_id="CY-AR-003",
            domain="Security Architecture",
            title="Software/Firmware Integrity",
            requirement=(
                "Mechanisms exist to authenticate software/firmware updates; "
                "unauthorized modifications detected at runtime or boot."
            ),
            guidance=(
                "Code signing for all software components and updates. "
                "Secure boot where applicable. "
                "Cryptographic hash verification of update packages before installation."
            ),
            references=["FDA Cyber 2023 §IV.B.3", "IEC 62443-3-3 SR 3.3", "NIST SP 800-193"],
            severity_if_missing=CyberSeverity.CRITICAL,
            is_mandatory_524b=True,
        ))

        self._add(CyberCheckItem(
            control_id="CY-AR-004",
            domain="Security Architecture",
            title="Network Security & Segmentation",
            requirement=(
                "Device enforces least-privilege network access; "
                "unnecessary ports/services disabled; network segmentation implemented."
            ),
            guidance=(
                "Document all open ports, protocols, and services. "
                "Restrict to minimum required for intended function. "
                "Firewall rules reviewed and documented. "
                "Segregate clinical device networks from general IT networks."
            ),
            references=["FDA Cyber 2023 §IV.B.4", "IEC 62443-3-3 SR 1.3", "NIST SP 800-82"],
            severity_if_missing=CyberSeverity.HIGH,
            is_mandatory_524b=False,
        ))

        self._add(CyberCheckItem(
            control_id="CY-AR-005",
            domain="Security Architecture",
            title="Audit Logging & Monitoring",
            requirement=(
                "Tamper-evident audit logs capture all security-relevant events "
                "(authentication, access, data modification, configuration changes)."
            ),
            guidance=(
                "Logs include: timestamp (UTC), user ID, action, source IP, outcome. "
                "Logs protected from deletion by unauthorized users. "
                "Log retention ≥ minimum required by applicable regulations (21 CFR Part 11: lifetime of device)."
            ),
            references=["21 CFR Part 11.10(e)", "FDA Cyber 2023 §IV.B.5", "NIST SP 800-92", "HIPAA 164.312(b)"],
            severity_if_missing=CyberSeverity.HIGH,
            is_mandatory_524b=True,
        ))

        self._add(CyberCheckItem(
            control_id="CY-AR-006",
            domain="Security Architecture",
            title="Secure Development Lifecycle (SDL)",
            requirement=(
                "A documented Secure Development Lifecycle (SDL) is followed, "
                "including threat modeling, secure coding standards, and security code review."
            ),
            guidance=(
                "Align with IEC 62443-4-1 secure product development lifecycle. "
                "Static Application Security Testing (SAST) and Dynamic Application "
                "Security Testing (DAST) integrated into CI/CD pipeline."
            ),
            references=["IEC 62443-4-1", "FDA Cyber 2023 §III.A", "OWASP SAMM"],
            severity_if_missing=CyberSeverity.HIGH,
            is_mandatory_524b=False,
        ))

        # ---------------------------------------------------------------
        # DOMAIN 3: Cybersecurity Testing
        # ---------------------------------------------------------------
        self._add(CyberCheckItem(
            control_id="CY-TS-001",
            domain="Cybersecurity Testing",
            title="Security Testing in Verification & Validation",
            requirement=(
                "Cybersecurity testing integrated into V&V activities covering "
                "known vulnerability scanning, fuzz testing, and penetration testing."
            ),
            guidance=(
                "Testing should cover OWASP Top 10, known CVEs in SOUP components. "
                "Penetration test by qualified tester before each major release. "
                "Document testing methodology, scope, findings, and remediation."
            ),
            references=["FDA Cyber 2023 §V.A", "IEC 62304 §5.6", "OWASP Testing Guide v4"],
            severity_if_missing=CyberSeverity.HIGH,
            is_mandatory_524b=True,
        ))

        self._add(CyberCheckItem(
            control_id="CY-TS-002",
            domain="Cybersecurity Testing",
            title="Third-Party / SOUP Component Vulnerability Assessment",
            requirement=(
                "All third-party software components (SOUP) assessed for known "
                "vulnerabilities; CVE scanning integrated into build pipeline."
            ),
            guidance=(
                "Automated CVE scanning against NVD/NIST database in CI/CD. "
                "Policy for handling CVSS ≥ 7.0 vulnerabilities before release. "
                "SOUP vulnerability assessment documented in Risk Management File."
            ),
            references=["FDA Cyber 2023 §IV.A.2", "NVD NIST", "IEC 62304 §8.1.2"],
            severity_if_missing=CyberSeverity.HIGH,
            is_mandatory_524b=True,
        ))

        # ---------------------------------------------------------------
        # DOMAIN 4: Transparency (SBOM & Vulnerability Disclosure)
        # ---------------------------------------------------------------
        self._add(CyberCheckItem(
            control_id="CY-TR-001",
            domain="Transparency",
            title="Software Bill of Materials (SBOM)",
            requirement=(
                "A comprehensive SBOM is maintained in machine-readable format "
                "(SPDX or CycloneDX) listing all software components, versions, "
                "and known vulnerabilities."
            ),
            guidance=(
                "SBOM is mandatory for cyber devices under FD&C §524B (submissions after 3/29/2023). "
                "Minimum SBOM fields per NTIA: supplier, component name, version, "
                "unique identifier, dependency relationship, author, timestamp. "
                "SBOM must be kept current throughout device lifecycle."
            ),
            references=["FD&C Act §524B(b)(3)", "FDA Cyber 2023 §IV.C", "NTIA SBOM Minimum Elements (2021)", "SPDX 2.3"],
            severity_if_missing=CyberSeverity.CRITICAL,
            is_mandatory_524b=True,
        ))

        self._add(CyberCheckItem(
            control_id="CY-TR-002",
            domain="Transparency",
            title="Coordinated Vulnerability Disclosure Policy",
            requirement=(
                "A publicly accessible coordinated vulnerability disclosure (CVD) "
                "policy exists, enabling third parties to report security vulnerabilities."
            ),
            guidance=(
                "Policy should include: how to report, response timeline, disclosure timeline. "
                "Align with ISO/IEC 30111 (Vulnerability Handling) and ISO/IEC 29147. "
                "Register with CISA and consider CVE Numbering Authority (CNA) partnership."
            ),
            references=["FD&C Act §524B(b)(2)", "FDA Cyber 2023 §IV.D", "ISO/IEC 29147", "CISA CVD"],
            severity_if_missing=CyberSeverity.HIGH,
            is_mandatory_524b=True,
        ))

        self._add(CyberCheckItem(
            control_id="CY-TR-003",
            domain="Transparency",
            title="Cybersecurity Labeling",
            requirement=(
                "Device labeling (IFU/product page) includes cybersecurity information: "
                "network requirements, security features, known limitations, and update instructions."
            ),
            guidance=(
                "Consider FDA's voluntary cybersecurity label program. "
                "Disclose: supported lifetime, patch policy, minimum security config. "
                "MDS2 (Manufacturer Disclosure Statement for Medical Device Security) recommended."
            ),
            references=["FDA Cyber 2023 §VII", "HIMSS MDS2", "FDA 21 CFR 801"],
            severity_if_missing=CyberSeverity.MEDIUM,
            is_mandatory_524b=False,
        ))

        # ---------------------------------------------------------------
        # DOMAIN 5: Post-Market / TPLC
        # ---------------------------------------------------------------
        self._add(CyberCheckItem(
            control_id="CY-PM-001",
            domain="Post-Market",
            title="Cybersecurity Patch Management Plan",
            requirement=(
                "A documented plan exists for releasing security patches, "
                "including critical patches within defined timelines."
            ),
            guidance=(
                "Critical patches (CVSS ≥ 9.0): release within 30 days. "
                "High patches (CVSS 7.0-8.9): release within 90 days. "
                "Patches must be validated per abbreviated V&V before release. "
                "FDA expects timely patching; unpatched critical vulns may require MDR."
            ),
            references=["FD&C Act §524B(b)(4)", "FDA Cyber 2023 §VI", "FDA Postmarket Cyber 2016"],
            severity_if_missing=CyberSeverity.HIGH,
            is_mandatory_524b=True,
        ))

        self._add(CyberCheckItem(
            control_id="CY-PM-002",
            domain="Post-Market",
            title="Security Incident Response Plan",
            requirement=(
                "A documented cybersecurity incident response plan covers: "
                "detection, containment, eradication, recovery, and FDA reporting."
            ),
            guidance=(
                "Align with NIST SP 800-61. "
                "Define patient safety escalation path: when does a cyber incident "
                "become an MDR-reportable event? "
                "Coordinate with facility CISO and CERT/ISAC (H-ISAC for healthcare)."
            ),
            references=["FDA Postmarket Cyber 2016 §IV.D", "NIST SP 800-61", "FDA MDR 21 CFR 803", "H-ISAC"],
            severity_if_missing=CyberSeverity.HIGH,
            is_mandatory_524b=False,
        ))

        self._add(CyberCheckItem(
            control_id="CY-PM-003",
            domain="Post-Market",
            title="End-of-Life (EOL) Security Support Plan",
            requirement=(
                "Device has documented end-of-life date with security support commitment "
                "and transition guidance for customers after EOL."
            ),
            guidance=(
                "FDA expects manufacturers to support devices throughout their useful life. "
                "Legacy device support: document known vulnerabilities, compensating controls. "
                "FDA may request recall for devices with exploitable unpatched vulnerabilities."
            ),
            references=["FD&C Act §524B", "FDA Cyber 2023 §VI.B", "FDA Postmarket Cyber 2016"],
            severity_if_missing=CyberSeverity.MEDIUM,
            is_mandatory_524b=False,
        ))

    def _add(self, item: CyberCheckItem):
        self.controls.append(item)

    def run_automated_checks(self) -> List[CyberCheckItem]:
        """
        Run what automated checks are possible.
        Most checks require human review; this sets obvious defaults.
        """
        # If SBOM is not provided, flag it
        if self.sbom is None:
            for c in self.controls:
                if c.control_id == "CY-TR-001":
                    c.status = CyberControlStatus.NON_COMPLIANT
                    c.finding = "No SBOM object provided to checker."
                    c.recommendation = "Generate SBOM using SBOMGenerator and pass to checker."
        return self.controls

    @property
    def mandatory_524b_controls(self) -> List[CyberCheckItem]:
        return [c for c in self.controls if c.is_mandatory_524b]

    @property
    def compliant_count(self) -> int:
        return sum(1 for c in self.controls if c.status == CyberControlStatus.COMPLIANT)

    @property
    def non_compliant_count(self) -> int:
        return sum(1 for c in self.controls if c.status == CyberControlStatus.NON_COMPLIANT)

    def summary(self) -> Dict:
        return {
            "Device": self.device.name,
            "Standard": "FDA Cybersecurity Guidance 2023 + FD&C §524B",
            "Total Controls": len(self.controls),
            "§524B Mandatory Controls": len(self.mandatory_524b_controls),
            "Compliant": self.compliant_count,
            "Non-Compliant": self.non_compliant_count,
            "Not Assessed": sum(1 for c in self.controls if c.status == CyberControlStatus.NOT_ASSESSED),
        }

    def print_summary(self):
        print("\n" + "="*70)
        print("FDA 2023 CYBERSECURITY CHECKLIST SUMMARY")
        print("="*70)
        for k, v in self.summary().items():
            print(f"  {k:<40} {v}")
        print("\nControl Register:")
        print(f"  {'ID':<14} {'Domain':<28} {'§524B':<7} {'Status'}")
        print("  " + "-"*68)
        for c in self.controls:
            mandatory = "YES" if c.is_mandatory_524b else "no"
            print(f"  {c.control_id:<14} {c.domain:<28} {mandatory:<7} {c.status.value}")
        print()
