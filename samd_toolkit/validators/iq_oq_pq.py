"""
samd_toolkit/validators/iq_oq_pq.py
=====================================
IQ / OQ / PQ Protocol Generator for SaMD.

References:
- GAMP 5 (Second Edition, 2022) — A Risk-Based Approach to GxP-Compliant Computerized Systems
- FDA 21 CFR Part 820.70 — Production and Process Controls
- FDA 21 CFR Part 820.75 — Process Validation
- IEC 62304:2006+AMD1:2015 — Medical Device Software Lifecycle
- ISPE Baseline Guide Vol. 5 — Commissioning and Qualification

IQ  = Installation Qualification  — Was the system installed correctly?
OQ  = Operational Qualification   — Does the system operate as designed?
PQ  = Performance Qualification   — Does the system perform in actual use?
"""

from __future__ import annotations
from typing import List, Dict
from ..core import (
    SaMDDevice, DeviceClass, SoftwareSafetyClass,
    ValidationSession, ValidationItem, ValidationStatus
)


# ---------------------------------------------------------------------------
# IQ — Installation Qualification
# ---------------------------------------------------------------------------

class InstallationQualification:
    """
    Verifies that the SaMD system is installed correctly and that
    all components match the design specification.

    Per IEC 62304 §5.8: Software maintenance / configuration management.
    Per FDA 21 CFR 820.70(i): Ensure software is validated prior to use.
    """

    def __init__(self, device: SaMDDevice):
        self.device = device
        self.items: List[ValidationItem] = []
        self._build_protocol()

    def _build_protocol(self):
        d = self.device
        dc = d.device_class
        sc = d.software_safety_class

        # IQ-001: Environment Specification Verification
        self._add("IQ-001", "Environment",
            requirement="Hardware and OS environment matches approved specification",
            criteria="All hardware specs ≥ minimum requirements; OS version matches IDS",
            method="Compare installed environment against Installation Design Specification (IDS)",
            ref="IEC 62304 §5.1; FDA 21 CFR 820.70(b)")

        # IQ-002: Software Installation Verification
        self._add("IQ-002", "Installation",
            requirement="SaMD software installs without error from approved media",
            criteria="Installation completes with exit code 0; no error messages in install log",
            method="Execute installation procedure per IFU; capture installer log",
            ref="IEC 62304 §5.8.1; GAMP 5 Appendix M2")

        # IQ-003: Version Verification
        self._add("IQ-003", "Version Control",
            requirement=f"Installed version matches approved release {d.version}",
            criteria=f"System displays version {d.version}; matches SOUP/component BOM",
            method="Navigate to About screen or run --version CLI; cross-check with SOUP list",
            ref="IEC 62304 §8.1.2; FDA SaMD Guidance Sec. IV")

        # IQ-004: Configuration Baseline
        self._add("IQ-004", "Configuration",
            requirement="All configuration files match baseline configuration specification",
            criteria="Hash values of config files match approved baseline manifest",
            method="Run checksum verification script; compare against approved hash manifest",
            ref="IEC 62304 §8.1.3; 21 CFR Part 11.10(k)")

        # IQ-005: Database Installation (if applicable)
        self._add("IQ-005", "Database",
            requirement="Database schemas created correctly per data architecture specification",
            criteria="All tables, indexes, and constraints created without error; schema version matches spec",
            method="Execute DB schema inspection query; compare to approved DB design document",
            ref="IEC 62304 §5.3; FDA 21 CFR 820.70(i)")

        # IQ-006: Network Configuration
        if d.network_connected:
            self._add("IQ-006", "Network",
                requirement="Network interfaces configured per approved network architecture",
                criteria="Correct IP/FQDN; required ports open; unauthorized ports closed; TLS 1.3 enforced",
                method="Network port scan; SSL/TLS handshake verification; firewall rule review",
                ref="FDA Cybersecurity Guidance 2023 §III.A; IEC 62443-3-3 SR 1.3")

        # IQ-007: Security Configuration
        self._add("IQ-007", "Security Baseline",
            requirement="Security hardening baseline applied per approved security configuration spec",
            criteria="Default credentials changed; unnecessary services disabled; audit logging enabled",
            method="Security baseline checklist walkthrough; automated CIS benchmark scan",
            ref="FDA Cybersecurity Guidance 2023 §IV; NIST SP 800-53 CM-6")

        # IQ-008: Backup and Recovery System
        self._add("IQ-008", "Backup",
            requirement="Backup system installed and configured per disaster recovery plan",
            criteria="Backup job scheduled; test backup completes within RPO; restore tested",
            method="Execute test backup; verify backup integrity; perform restore drill",
            ref="IEC 62304 §6.2.5; FDA 21 CFR 820.180(c)")

        # IQ-009: User Access Control Setup
        self._add("IQ-009", "Access Control",
            requirement="User roles and permissions configured per access control matrix",
            criteria="Admin, Clinical, Read-Only roles exist; permissions match access matrix",
            method="Create test users in each role; verify access per permission matrix",
            ref="21 CFR Part 11.10(d); IEC 62443-3-3 SR 1.1")

        # IQ-010: Audit Trail Configuration (Class II/III)
        if dc in (DeviceClass.CLASS_II, DeviceClass.CLASS_III):
            self._add("IQ-010", "Audit Trail",
                requirement="Electronic audit trail enabled and tamper-evident per 21 CFR Part 11",
                criteria="All create/modify/delete events logged with timestamp, user ID, and action",
                method="Perform test CRUD operations; verify audit log entries; attempt log deletion (should fail)",
                ref="21 CFR Part 11.10(e); FDA 21 CFR 820.181")

        # IQ-011: SOUP/Third-Party Component Verification
        if sc in (SoftwareSafetyClass.CLASS_B, SoftwareSafetyClass.CLASS_C):
            self._add("IQ-011", "SOUP Verification",
                requirement="All Software of Unknown Provenance (SOUP) components match approved SOUP list",
                criteria="Each installed third-party library version matches SOUP list; no unapproved libraries present",
                method="Run dependency audit (pip list, npm list); compare to SOUP register",
                ref="IEC 62304 §8.1.2; FDA SaMD Guidance Appendix")

        # IQ-012: Regulatory Documentation Package
        self._add("IQ-012", "Documentation",
            requirement="All required regulatory documentation available at installation site",
            criteria="IFU, Risk Management File, System Design Spec, and this IQ protocol present and approved",
            method="Document checklist review; verify approval signatures and revision control",
            ref="IEC 62304 §5.1.8; FDA 21 CFR 820.40")

    def _add(self, item_id, section, requirement, criteria, method, ref):
        self.items.append(ValidationItem(
            item_id=item_id,
            section=section,
            requirement=requirement,
            acceptance_criteria=criteria,
            test_method=method,
            reference_standard=ref,
        ))


# ---------------------------------------------------------------------------
# OQ — Operational Qualification
# ---------------------------------------------------------------------------

class OperationalQualification:
    """
    Verifies that the SaMD system operates according to its design specification
    across the full operational range, including boundary and error conditions.

    Per IEC 62304 §5.6: Software integration testing.
    Per GAMP 5: Testing must demonstrate the system does what it is designed to do.
    """

    def __init__(self, device: SaMDDevice):
        self.device = device
        self.items: List[ValidationItem] = []
        self._build_protocol()

    def _build_protocol(self):
        d = self.device
        dc = d.device_class

        # OQ-001: Core Functional Testing
        self._add("OQ-001", "Core Functionality",
            requirement="All primary use case workflows execute correctly per functional specification",
            criteria="Each defined use case completes successfully; output matches expected result",
            method="Execute test scripts for each functional requirement; record pass/fail per test case",
            ref="IEC 62304 §5.6; FDA SaMD Guidance Sec. V")

        # OQ-002: Input Validation
        self._add("OQ-002", "Input Validation",
            requirement="System correctly validates all user and data inputs",
            criteria="Valid inputs accepted; invalid inputs rejected with appropriate error message; no crash on boundary values",
            method="Test matrix: valid, invalid, null, boundary, injection attack inputs; verify response per spec",
            ref="IEC 62304 §5.5.3; OWASP Top 10 A03:2021")

        # OQ-003: Algorithm / Computation Accuracy
        self._add("OQ-003", "Algorithm Accuracy",
            requirement="All computational algorithms produce correct results within specified tolerance",
            criteria="Algorithm output matches reference standard within ±tolerance defined in SRS",
            method="Unit tests with known ground-truth datasets; statistical accuracy metrics (sensitivity, specificity)",
            ref="IEC 62304 §5.5.4; FDA AI/ML Action Plan 2021")

        # OQ-004: User Interface Validation
        self._add("OQ-004", "User Interface",
            requirement="All UI elements function as specified and IEC 62366 usability requirements met",
            criteria="All buttons, forms, navigation, and displays function per UI specification; no broken elements",
            method="Manual walkthrough of all UI screens; scripted UI automation tests",
            ref="IEC 62366-1:2015 Usability Engineering; FDA Human Factors Guidance")

        # OQ-005: Error Handling and Recovery
        self._add("OQ-005", "Error Handling",
            requirement="System handles errors gracefully without data loss or unsafe state",
            criteria="Error conditions produce user-readable messages; system recovers to safe state; no data corruption",
            method="Inject error conditions (network loss, DB timeout, invalid data); verify recovery behavior",
            ref="IEC 62304 §5.5.3; ISO 14971 §10 — Risk controls effectiveness")

        # OQ-006: Interoperability Testing
        if d.interoperates_with_ehr:
            self._add("OQ-006", "EHR Interoperability",
                requirement="SaMD correctly exchanges data with EHR systems per HL7 FHIR R4 specification",
                criteria="Patient data reads/writes succeed; FHIR resource validation passes; no data mapping errors",
                method="HL7 FHIR conformance test suite; integration testing with EHR sandbox environment",
                ref="HL7 FHIR R4; 21st Century Cures Act Interoperability Rules; ONC §170.315(g)(9)")

        # OQ-007: AI/ML Model Validation
        if d.contains_ai_ml:
            self._add("OQ-007", "AI/ML Model Validation",
                requirement="AI/ML algorithm performs within specified clinical performance bounds",
                criteria="Sensitivity ≥ spec threshold; Specificity ≥ spec threshold; AUC ≥ spec on validation dataset",
                method="Run model against locked validation dataset; compute confusion matrix and ROC AUC",
                ref="FDA AI/ML Action Plan 2021; FDA SaMD Guidance Sec. V.B; IEC 62304 §5.5")

        # OQ-008: Security Functional Testing
        self._add("OQ-008", "Security Functions",
            requirement="Authentication, authorization, and encryption functions operate per security specification",
            criteria="Login enforces password policy; role-based access enforced; data encrypted at rest/transit",
            method="Penetration test: brute force, session hijack attempt, privilege escalation, PHI exposure test",
            ref="FDA Cybersecurity Guidance 2023 §III; NIST SP 800-63B; HIPAA 164.312")

        # OQ-009: Audit Trail Functional Testing
        self._add("OQ-009", "Audit Trail Functionality",
            requirement="Audit trail correctly records all regulated operations",
            criteria="Each regulated action produces an audit record with timestamp (UTC), user, action, and record ID",
            method="Perform regulated operations; verify each entry in audit log; test cannot-delete constraint",
            ref="21 CFR Part 11.10(e); FDA 21 CFR 820.181")

        # OQ-010: Performance Under Load
        self._add("OQ-010", "Performance",
            requirement="System meets response time requirements under specified concurrent user load",
            criteria="P95 response time ≤ spec (e.g., <2s) under load of N concurrent users; no errors under load",
            method="Load testing tool (Locust/JMeter) at 1x, 2x, 5x expected load; monitor response times and errors",
            ref="IEC 62304 §5.5.4; FDA 21 CFR 820.70(b) — Production Controls")

        # OQ-011: Data Integrity
        self._add("OQ-011", "Data Integrity",
            requirement="Data is stored, retrieved, and transmitted without corruption or loss",
            criteria="CRC/hash verification passes after storage/retrieval; no data truncation; encoding correct",
            method="Write known data; retrieve and compare; simulate transmission corruption; verify detection",
            ref="21 CFR Part 11.10(a); IEC 62304 §5.5; ISO 14971 Risk Control")

        # OQ-012: Regulatory Compliance Functions (Class II/III)
        if dc in (DeviceClass.CLASS_II, DeviceClass.CLASS_III):
            self._add("OQ-012", "Regulatory Compliance Functions",
                requirement="All regulatory-specific software functions operate correctly",
                criteria="Electronic signature workflow; 21 CFR Part 11 records locked; HIPAA PHI de-id functions work",
                method="End-to-end electronic signature test; PHI de-identification functional test",
                ref="21 CFR Part 11; HIPAA 45 CFR §164.514; FDA 21 CFR 820.65")

    def _add(self, item_id, section, requirement, criteria, method, ref):
        self.items.append(ValidationItem(
            item_id=item_id,
            section=section,
            requirement=requirement,
            acceptance_criteria=criteria,
            test_method=method,
            reference_standard=ref,
        ))


# ---------------------------------------------------------------------------
# PQ — Performance Qualification
# ---------------------------------------------------------------------------

class PerformanceQualification:
    """
    Demonstrates that the SaMD consistently performs as intended under
    real-world conditions and clinical use scenarios.

    PQ is the final gate before production deployment.
    Per GAMP 5: PQ validates the process (not just the system) in actual use.
    Per IEC 62304 §5.7: Software release; system-level testing.
    """

    def __init__(self, device: SaMDDevice):
        self.device = device
        self.items: List[ValidationItem] = []
        self._build_protocol()

    def _build_protocol(self):
        d = self.device
        dc = d.device_class

        # PQ-001: Clinical Scenario Simulation
        self._add("PQ-001", "Clinical Scenarios",
            requirement="SaMD correctly handles representative clinical use scenarios including edge cases",
            criteria="All defined clinical test scenarios pass; no unsafe outputs on edge case inputs",
            method="Execute clinical scenario test plan with realistic patient data (de-identified); score outcomes",
            ref="FDA SaMD Guidance Sec. V; IEC 62304 §5.7; ISO 14971 §7 — Risk evaluation")

        # PQ-002: User Acceptance Testing (UAT)
        self._add("PQ-002", "User Acceptance Testing",
            requirement="Intended users can successfully use the system to accomplish intended use",
            criteria="≥90% task completion rate in UAT; no critical usability issues; SUS score ≥ 68",
            method="UAT sessions with representative end users (HCPs/patients); observe task completion; SUS questionnaire",
            ref="IEC 62366-1:2015 §5.9; FDA Human Factors Guidance; ANSI/AAMI HE75")

        # PQ-003: Long-Duration Stability Testing
        self._add("PQ-003", "Stability / Soak Test",
            requirement="System remains stable under continuous operation over extended period",
            criteria="No memory leaks, crashes, or performance degradation over 72-hour soak test",
            method="Run system under representative load for 72 hours; monitor memory, CPU, error rate",
            ref="IEC 62304 §5.7; FDA 21 CFR 820.70(b)")

        # PQ-004: Disaster Recovery / Business Continuity
        self._add("PQ-004", "Disaster Recovery",
            requirement="System recovers from catastrophic failure within defined RTO/RPO",
            criteria=f"System restored to full operation within RTO; data loss ≤ RPO; all audit trails intact",
            method="Simulate server failure; execute DR runbook; measure actual RTO/RPO",
            ref="IEC 62304 §6.2.5; NIST SP 800-34; FDA 21 CFR 820.180(c)")

        # PQ-005: Concurrent User / Multi-site Testing
        self._add("PQ-005", "Concurrent Operations",
            requirement="System correctly handles simultaneous operations by multiple users without data collision",
            criteria="No data corruption under concurrent writes; correct locking behavior; consistent reads",
            method="Concurrent user simulation with scripted concurrent workflows; verify data integrity post-test",
            ref="IEC 62304 §5.7; FDA 21 CFR 820.70")

        # PQ-006: Clinical Decision Support Output Validation (Class II/III)
        if dc in (DeviceClass.CLASS_II, DeviceClass.CLASS_III):
            self._add("PQ-006", "CDS Output Clinical Validity",
                requirement="Clinical decision support outputs are clinically appropriate and match reference standard",
                criteria="Algorithm output agrees with physician/reference standard in ≥N% of cases per clinical validation plan",
                method="Retrospective validation study with locked clinical dataset; statistical analysis vs. reference standard",
                ref="FDA CDS Guidance 2019; FDA SaMD Guidance Sec. V.B; AUC/ROC analysis")

        # PQ-007: Cybersecurity Penetration Test
        if d.network_connected:
            self._add("PQ-007", "Penetration Test",
                requirement="System withstands external and internal attack simulation per cybersecurity test plan",
                criteria="No critical or high CVSS vulnerabilities exploited; PHI not accessible to unauthorized actors",
                method="Third-party penetration test; OWASP Top 10; ASVS Level 2 verification",
                ref="FDA Cybersecurity Guidance 2023 §IV.B; OWASP ASVS 4.0; IEC 62443-4-1")

        # PQ-008: AI/ML Real-World Performance Monitoring Baseline
        if d.contains_ai_ml:
            self._add("PQ-008", "AI/ML Production Monitoring Baseline",
                requirement="AI/ML model performance monitoring established with defined drift detection thresholds",
                criteria="Baseline metrics (sensitivity, specificity, AUC) recorded; alerting configured for ≥5% drift",
                method="Deploy monitoring dashboard; record baseline metrics on production data sample; verify alerts",
                ref="FDA AI/ML Action Plan 2021; FDA PCCP Guidance; IEC 62304 §6.1")

        # PQ-009: Training and Competency Verification
        self._add("PQ-009", "Training Verification",
            requirement="All identified user groups complete device training and pass competency assessment",
            criteria="100% of clinical users trained; ≥80% competency test score; training records filed in QMS",
            method="Review training completion records; spot-check competency assessment scores",
            ref="IEC 62366-1 §5.10; FDA 21 CFR 820.25; MDR 2017/745 Article 10(10)")

        # PQ-010: Final Release Authorization
        self._add("PQ-010", "Release Authorization",
            requirement="All PQ criteria met; all deviations closed or formally accepted; QA release authorization obtained",
            criteria="Pass rate 100% (or all failures formally accepted with deviation report); QA sign-off on record",
            method="Review PQ execution summary; confirm deviation disposition; obtain QA release signature",
            ref="IEC 62304 §5.8; FDA 21 CFR 820.80(d); ISO 13485 §8.2.6")

    def _add(self, item_id, section, requirement, criteria, method, ref):
        self.items.append(ValidationItem(
            item_id=item_id,
            section=section,
            requirement=requirement,
            acceptance_criteria=criteria,
            test_method=method,
            reference_standard=ref,
        ))


# ---------------------------------------------------------------------------
# Main Generator
# ---------------------------------------------------------------------------

class IQOQPQGenerator:
    """
    Generates a complete IQ/OQ/PQ validation package for a SaMD device.

    Usage:
        device = SaMDDevice(name="CardioWatch AI", ...)
        gen = IQOQPQGenerator(device)
        session = gen.generate_full_package()
    """

    def __init__(self, device: SaMDDevice):
        self.device = device
        self.iq = InstallationQualification(device)
        self.oq = OperationalQualification(device)
        self.pq = PerformanceQualification(device)

    def generate_full_package(
        self,
        prepared_by: str = "",
        site: str = "",
    ) -> ValidationSession:
        """Build and return a fully populated ValidationSession."""
        session = ValidationSession(
            device=self.device,
            protocol_type="IQ/OQ/PQ",
            prepared_by=prepared_by,
            site=site,
        )
        for item in self.iq.items:
            session.add_item(item)
        for item in self.oq.items:
            session.add_item(item)
        for item in self.pq.items:
            session.add_item(item)
        return session

    def generate_iq_only(self) -> ValidationSession:
        session = ValidationSession(device=self.device, protocol_type="IQ")
        for item in self.iq.items:
            session.add_item(item)
        return session

    def generate_oq_only(self) -> ValidationSession:
        session = ValidationSession(device=self.device, protocol_type="OQ")
        for item in self.oq.items:
            session.add_item(item)
        return session

    def generate_pq_only(self) -> ValidationSession:
        session = ValidationSession(device=self.device, protocol_type="PQ")
        for item in self.pq.items:
            session.add_item(item)
        return session

    def item_count_by_protocol(self) -> Dict[str, int]:
        return {
            "IQ": len(self.iq.items),
            "OQ": len(self.oq.items),
            "PQ": len(self.pq.items),
            "Total": len(self.iq.items) + len(self.oq.items) + len(self.pq.items),
        }
