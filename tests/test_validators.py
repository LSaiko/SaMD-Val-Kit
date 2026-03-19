"""
tests/test_validators.py
==========================
Unit tests for IQ/OQ/PQ validators and core models.

Run with: pytest tests/test_validators.py -v
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from samd_toolkit.core import (
    SaMDDevice, DeviceClass, SoftwareSafetyClass, ValidationSession,
    ValidationItem, ValidationStatus, RegulatoryPathway
)
from samd_toolkit.validators.iq_oq_pq import (
    IQOQPQGenerator, InstallationQualification,
    OperationalQualification, PerformanceQualification
)
from samd_toolkit.standards.iso14971 import (
    RiskManagementFile, RiskItem, RiskAcceptability, RISK_MATRIX
)
from samd_toolkit.standards.imdrf import (
    IMDRFCategorizer, HealthcareState, SignificanceOfOutput
)
from samd_toolkit.standards.iec62304 import IEC62304LifecycleValidator
from samd_toolkit.cybersecurity.fda_cyber import FDACybersecurityChecker
from samd_toolkit.cybersecurity.sbom import SBOMGenerator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def class_i_device():
    return SaMDDevice(
        name="WellTrack", version="1.0", manufacturer="HealthSoft",
        device_class=DeviceClass.CLASS_I,
        software_safety_class=SoftwareSafetyClass.CLASS_A,
        intended_use="General wellness activity tracking",
        network_connected=True, contains_ai_ml=False, processes_phi=False,
    )


@pytest.fixture
def class_ii_device():
    return SaMDDevice(
        name="CardioWatch AI", version="2.1.0", manufacturer="MedTech Corp",
        device_class=DeviceClass.CLASS_II,
        software_safety_class=SoftwareSafetyClass.CLASS_B,
        intended_use="AI-driven ECG arrhythmia detection",
        predicate_device="iRhythm Zio AT (K192613)",
        network_connected=True, contains_ai_ml=True,
        processes_phi=True, interoperates_with_ehr=True,
    )


@pytest.fixture
def class_iii_device():
    return SaMDDevice(
        name="InsulinAI", version="1.0.0", manufacturer="DiabetesTech",
        device_class=DeviceClass.CLASS_III,
        software_safety_class=SoftwareSafetyClass.CLASS_C,
        intended_use="Closed-loop automated insulin delivery",
        regulatory_pathway=RegulatoryPathway.PMA,
        network_connected=True, contains_ai_ml=True,
        processes_phi=True, interoperates_with_ehr=True,
    )


# ---------------------------------------------------------------------------
# Core Model Tests
# ---------------------------------------------------------------------------

class TestSaMDDevice:

    def test_class_i_auto_infers_exempt_pathway(self, class_i_device):
        assert class_i_device.regulatory_pathway == RegulatoryPathway.EXEMPT

    def test_class_ii_auto_infers_510k_pathway(self, class_ii_device):
        assert class_ii_device.regulatory_pathway == RegulatoryPathway.K510

    def test_class_iii_auto_infers_pma_pathway(self, class_iii_device):
        assert class_iii_device.regulatory_pathway == RegulatoryPathway.PMA

    def test_device_summary_contains_required_fields(self, class_ii_device):
        summary = class_ii_device.summary()
        required_keys = ["Device Name", "FDA Class", "Risk Level",
                         "IEC 62304 Safety Class", "Regulatory Pathway"]
        for key in required_keys:
            assert key in summary

    def test_risk_label_reflects_class(self, class_iii_device):
        assert "High Risk" in class_iii_device.risk_label
        assert "PMA" in class_iii_device.risk_label


# ---------------------------------------------------------------------------
# IQ/OQ/PQ Generator Tests
# ---------------------------------------------------------------------------

class TestIQOQPQGenerator:

    def test_class_iii_has_more_items_than_class_i(self, class_i_device, class_iii_device):
        gen_i = IQOQPQGenerator(class_i_device)
        gen_iii = IQOQPQGenerator(class_iii_device)
        assert gen_iii.item_count_by_protocol()["Total"] > gen_i.item_count_by_protocol()["Total"]

    def test_ai_ml_device_has_ai_specific_items(self, class_ii_device):
        gen = IQOQPQGenerator(class_ii_device)
        session = gen.generate_full_package()
        ai_items = session.get_by_section("AI/ML Model Validation")
        assert len(ai_items) > 0

    def test_network_device_has_network_iq_item(self, class_ii_device):
        iq = InstallationQualification(class_ii_device)
        network_items = [i for i in iq.items if i.section == "Network"]
        assert len(network_items) > 0

    def test_non_network_device_no_network_iq_item(self):
        device = SaMDDevice(
            name="OfflineApp", version="1.0", manufacturer="Corp",
            device_class=DeviceClass.CLASS_I,
            software_safety_class=SoftwareSafetyClass.CLASS_A,
            intended_use="Offline wellness", network_connected=False,
        )
        iq = InstallationQualification(device)
        network_items = [i for i in iq.items if i.section == "Network"]
        assert len(network_items) == 0

    def test_full_package_has_iq_oq_pq_items(self, class_ii_device):
        gen = IQOQPQGenerator(class_ii_device)
        session = gen.generate_full_package()
        ids = [item.item_id for item in session.items]
        assert any(i.startswith("IQ-") for i in ids)
        assert any(i.startswith("OQ-") for i in ids)
        assert any(i.startswith("PQ-") for i in ids)

    def test_session_pass_rate(self, class_ii_device):
        gen = IQOQPQGenerator(class_ii_device)
        session = gen.generate_full_package()
        # Mark half as passed
        for item in session.items[:5]:
            item.mark_passed("tester", "OK")
        assert session.passed == 5
        assert session.pass_rate > 0


# ---------------------------------------------------------------------------
# ISO 14971 Risk Management Tests
# ---------------------------------------------------------------------------

class TestRiskManagement:

    def test_risk_matrix_covers_all_combinations(self):
        for p in range(1, 6):
            for s in range(1, 6):
                assert (p, s) in RISK_MATRIX

    def test_critical_high_risk_is_unacceptable(self):
        # P=5, S=5 must be UNACCEPTABLE
        assert RISK_MATRIX[(5, 5)] == RiskAcceptability.UNACCEPTABLE

    def test_low_risk_is_acceptable(self):
        # P=1, S=1 must be ACCEPTABLE
        assert RISK_MATRIX[(1, 1)] == RiskAcceptability.ACCEPTABLE

    def test_rmf_pre_populates_risks(self, class_ii_device):
        rmf = RiskManagementFile(class_ii_device)
        assert len(rmf.risks) > 0

    def test_class_iii_has_more_risks_than_class_i(self, class_i_device, class_iii_device):
        rmf_i = RiskManagementFile(class_i_device)
        rmf_iii = RiskManagementFile(class_iii_device)
        assert len(rmf_iii.risks) > len(rmf_i.risks)

    def test_risk_item_score_calculation(self):
        risk = RiskItem(probability_before=3, severity=4,
                        probability_after=1)
        assert risk.initial_risk_score == 12
        assert risk.residual_risk_score == 4

    def test_risk_reduction_achieved(self):
        risk = RiskItem(probability_before=3, severity=4, probability_after=1)
        assert risk.risk_reduction_achieved is True

    def test_overall_residual_risk_acceptable(self, class_ii_device):
        rmf = RiskManagementFile(class_ii_device)
        # After mitigations, pre-built risks should be acceptable or ALARP
        # (No unacceptable residual risks in the pre-populated set)
        assert rmf.overall_residual_risk_acceptable is True


# ---------------------------------------------------------------------------
# IMDRF Categorization Tests
# ---------------------------------------------------------------------------

class TestIMDRFCategorizer:

    def test_category_iv_for_treat_critical(self):
        cat = IMDRFCategorizer().categorize(
            HealthcareState.CRITICAL,
            SignificanceOfOutput.TREAT_OR_DIAGNOSE,
        )
        assert cat.category == 4

    def test_category_i_for_inform_non_serious(self):
        cat = IMDRFCategorizer().categorize(
            HealthcareState.NON_SERIOUS,
            SignificanceOfOutput.INFORM_MANAGEMENT,
        )
        assert cat.category == 1

    def test_category_iii_requires_clinical_validation(self):
        cat = IMDRFCategorizer().categorize(
            HealthcareState.SERIOUS,
            SignificanceOfOutput.TREAT_OR_DIAGNOSE,
        )
        assert cat.clinical_validation_required is True

    def test_category_i_no_clinical_validation_required(self):
        cat = IMDRFCategorizer().categorize(
            HealthcareState.NON_SERIOUS,
            SignificanceOfOutput.INFORM_MANAGEMENT,
        )
        assert cat.clinical_validation_required is False


# ---------------------------------------------------------------------------
# IEC 62304 Tests
# ---------------------------------------------------------------------------

class TestIEC62304:

    def test_class_c_has_more_requirements_than_class_a(self, class_i_device, class_iii_device):
        val_a = IEC62304LifecycleValidator(class_i_device)
        val_c = IEC62304LifecycleValidator(class_iii_device)
        assert len(val_c.required_activities()) > len(val_a.required_activities())

    def test_class_a_does_not_require_unit_testing(self, class_i_device):
        val = IEC62304LifecycleValidator(class_i_device)
        required = val.required_activities()
        unit_test = [a for a in required if "Unit" in a.activity]
        assert len(unit_test) == 0

    def test_class_c_requires_unit_testing(self, class_iii_device):
        val = IEC62304LifecycleValidator(class_iii_device)
        required = val.required_activities()
        unit_test = [a for a in required if "Unit" in a.activity]
        assert len(unit_test) > 0

    def test_gap_analysis_shows_100_percent_when_all_done(self, class_ii_device):
        val = IEC62304LifecycleValidator(class_ii_device)
        required = val.required_activities()
        all_sections = list(set(a.section for a in required))
        result = val.gap_analysis(completed_sections=all_sections)
        assert result["Gaps"] == 0


# ---------------------------------------------------------------------------
# SBOM Tests
# ---------------------------------------------------------------------------

class TestSBOM:

    def test_sbom_generates_components(self, class_ii_device):
        sbom = SBOMGenerator(class_ii_device).generate()
        assert len(sbom.components) > 0

    def test_ai_device_has_more_components(self, class_i_device, class_ii_device):
        sbom_i = SBOMGenerator(class_i_device).generate()
        sbom_ii = SBOMGenerator(class_ii_device).generate()
        assert len(sbom_ii.components) > len(sbom_i.components)

    def test_spdx_export_has_required_fields(self, class_ii_device):
        sbom = SBOMGenerator(class_ii_device).generate()
        spdx = sbom.export_spdx_json()
        assert spdx["spdxVersion"] == "SPDX-2.3"
        assert "packages" in spdx
        assert len(spdx["packages"]) == len(sbom.components)


# ---------------------------------------------------------------------------
# Cybersecurity Tests
# ---------------------------------------------------------------------------

class TestCybersecurity:

    def test_cybersecurity_has_524b_controls(self, class_ii_device):
        checker = FDACybersecurityChecker(class_ii_device)
        mandatory = checker.mandatory_524b_controls
        assert len(mandatory) > 0

    def test_sbom_control_mandatory_524b(self, class_ii_device):
        checker = FDACybersecurityChecker(class_ii_device)
        sbom_controls = [c for c in checker.controls if c.control_id == "CY-TR-001"]
        assert len(sbom_controls) == 1
        assert sbom_controls[0].is_mandatory_524b is True

    def test_all_controls_present(self, class_iii_device):
        checker = FDACybersecurityChecker(class_iii_device)
        # Should have controls across all 5 domains
        domains = set(c.domain for c in checker.controls)
        expected = {"Security Risk Management", "Security Architecture",
                    "Cybersecurity Testing", "Transparency", "Post-Market"}
        assert expected == domains
