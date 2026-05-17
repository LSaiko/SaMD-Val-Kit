"""
tests/test_validators.py
==========================
Unit tests for IQ/OQ/PQ validators and core models.

Run with: pytest tests/test_validators.py -v
"""

import pytest
import sys
import os
from datetime import timezone
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
        for item in session.items[:5]:
            item.mark_passed("J. Smith", "Meets acceptance criteria")
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


# ---------------------------------------------------------------------------
# Input Validation Tests (negative)
# ---------------------------------------------------------------------------

class TestValidationItemInputValidation:

    def _make_item(self):
        return ValidationItem(
            item_id="IQ-001", section="Environment",
            requirement="OS version verified",
            acceptance_criteria="Ubuntu 22.04 LTS",
            test_method="System inspection",
            reference_standard="IEC 62304 §5.8",
        )

    def test_mark_passed_rejects_empty_tester(self):
        item = self._make_item()
        with pytest.raises(ValueError, match="tester name"):
            item.mark_passed("", "System verified as Ubuntu 22.04 LTS")

    def test_mark_passed_rejects_whitespace_tester(self):
        item = self._make_item()
        with pytest.raises(ValueError, match="tester name"):
            item.mark_passed("   ", "System verified as Ubuntu 22.04 LTS")

    def test_mark_passed_rejects_trivial_result(self):
        item = self._make_item()
        with pytest.raises(ValueError, match="result description"):
            item.mark_passed("J. Smith", "OK")

    def test_mark_failed_rejects_empty_tester(self):
        item = self._make_item()
        with pytest.raises(ValueError, match="tester name"):
            item.mark_failed("", "OS version mismatch observed")

    def test_mark_failed_rejects_trivial_result(self):
        item = self._make_item()
        with pytest.raises(ValueError, match="result description"):
            item.mark_failed("J. Smith", "NO")

    def test_mark_passed_records_utc_timestamp(self):
        item = self._make_item()
        item.mark_passed("J. Smith", "Meets acceptance criteria — Ubuntu 22.04 confirmed")
        assert item.test_date is not None
        assert item.test_date.tzinfo is not None
        assert item.test_date.tzinfo == timezone.utc

    def test_mark_failed_records_utc_timestamp(self):
        item = self._make_item()
        item.mark_failed("J. Smith", "OS version mismatch — found 20.04", "Deviation DR-001")
        assert item.test_date is not None
        assert item.test_date.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# Risk Matrix Boundary Tests (negative)
# ---------------------------------------------------------------------------

class TestRiskMatrixBoundaries:

    def test_out_of_range_probability_raises(self):
        risk = RiskItem(probability_before=6, severity=3, probability_after=1)
        with pytest.raises(ValueError, match="Invalid risk matrix key"):
            _ = risk.initial_acceptability

    def test_zero_probability_raises(self):
        risk = RiskItem(probability_before=0, severity=3, probability_after=1)
        with pytest.raises(ValueError, match="Invalid risk matrix key"):
            _ = risk.initial_acceptability

    def test_out_of_range_severity_raises(self):
        risk = RiskItem(probability_before=2, severity=6, probability_after=1)
        with pytest.raises(ValueError, match="Invalid risk matrix key"):
            _ = risk.initial_acceptability

    def test_out_of_range_residual_probability_raises(self):
        risk = RiskItem(probability_before=2, severity=3, probability_after=0)
        with pytest.raises(ValueError, match="Invalid risk matrix key"):
            _ = risk.residual_acceptability


# ---------------------------------------------------------------------------
# UTC Timestamp Tests
# ---------------------------------------------------------------------------

class TestUTCTimestamps:

    def test_device_created_at_is_utc(self, class_ii_device):
        assert class_ii_device.created_at.tzinfo == timezone.utc

    def test_session_created_at_is_utc(self, class_ii_device):
        gen = IQOQPQGenerator(class_ii_device)
        session = gen.generate_full_package()
        assert session.created_at.tzinfo == timezone.utc

    def test_rmf_created_at_is_utc(self, class_ii_device):
        from samd_toolkit.standards.iso14971 import RiskManagementFile
        rmf = RiskManagementFile(class_ii_device)
        assert rmf.created_at.tzinfo == timezone.utc

    def test_sbom_generated_at_is_utc(self, class_ii_device):
        sbom = SBOMGenerator(class_ii_device).generate()
        assert sbom.generated_at.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# Integration Test — Full Pipeline
# ---------------------------------------------------------------------------

class TestFullPipeline:

    def test_class_ii_full_pipeline(self, class_ii_device):
        """End-to-end: device → IQ/OQ/PQ → risk mgmt → SBOM → cybersecurity → HTML export."""
        from samd_toolkit.standards.iso14971 import RiskManagementFile
        from samd_toolkit.standards.iec62304 import IEC62304LifecycleValidator
        from samd_toolkit.cybersecurity.fda_cyber import FDACybersecurityChecker
        from samd_toolkit.reports.html_reporter import HTMLReporter

        # IQ/OQ/PQ
        gen = IQOQPQGenerator(class_ii_device)
        session = gen.generate_full_package()
        assert session.total > 0

        # Mark a few items to exercise pass/fail paths
        session.items[0].mark_passed("J. Smith", "Environment verified as expected")
        session.items[1].mark_failed("J. Smith", "Unexpected service found running", "DR-001: remediated")
        assert session.passed == 1
        assert session.failed == 1

        # Risk Management
        rmf = RiskManagementFile(class_ii_device)
        assert rmf.overall_residual_risk_acceptable

        # IEC 62304
        val = IEC62304LifecycleValidator(class_ii_device)
        activities = val.required_activities()
        assert len(activities) > 0

        # SBOM
        sbom = SBOMGenerator(class_ii_device).generate()
        spdx = sbom.export_spdx_json()
        assert spdx["spdxVersion"] == "SPDX-2.3"
        assert len(spdx["packages"]) == len(sbom.components)

        # Cybersecurity
        checker = FDACybersecurityChecker(class_ii_device)
        assert len(checker.mandatory_524b_controls) > 0

        # HTML report (generates string — verify it's non-empty and has key markers)
        reporter = HTMLReporter(session)
        html = reporter.generate()
        assert "<html" in html.lower()
        assert class_ii_device.name in html

    def test_class_iii_full_pipeline_has_more_items_than_class_i(
        self, class_i_device, class_iii_device
    ):
        gen_i = IQOQPQGenerator(class_i_device)
        gen_iii = IQOQPQGenerator(class_iii_device)
        session_i = gen_i.generate_full_package()
        session_iii = gen_iii.generate_full_package()
        assert session_iii.total > session_i.total


# ---------------------------------------------------------------------------
# Serialisation Round-Trip Tests
# ---------------------------------------------------------------------------

class TestSerialisation:

    def test_validation_item_to_dict_round_trip(self):
        item = ValidationItem(
            item_id="IQ-099", section="Environment",
            requirement="OS version verified",
            acceptance_criteria="Ubuntu 22.04 LTS",
            test_method="System inspection",
            reference_standard="IEC 62304 §5.8",
        )
        item.mark_passed("J. Smith", "Ubuntu 22.04 LTS confirmed on target server")
        d = item.to_dict()
        assert d["ID"] == "IQ-099"
        assert d["Status"] == "Passed"
        assert d["Tester"] == "J. Smith"
        assert d["Test Date"] != ""  # ISO timestamp present

    def test_device_summary_all_fields_serialisable(self, class_iii_device):
        import json
        summary = class_iii_device.summary()
        # All values must be JSON-serialisable (str/bool/int/float)
        json_str = json.dumps(summary)
        assert class_iii_device.name in json_str

    def test_risk_item_to_dict_round_trip(self):
        import json
        risk = RiskItem(
            risk_id="RISK-TEST",
            hazard="Test hazard",
            probability_before=2, severity=3,
            probability_after=1,
        )
        d = risk.to_dict()
        json_str = json.dumps(d)
        assert "RISK-TEST" in json_str
        assert d["Initial Risk Score"] == 6
        assert d["Residual Risk Score"] == 3

    def test_spdx_export_is_json_serialisable(self, class_ii_device):
        import json
        sbom = SBOMGenerator(class_ii_device).generate()
        spdx = sbom.export_spdx_json()
        json_str = json.dumps(spdx)
        assert "SPDX-2.3" in json_str


# ---------------------------------------------------------------------------
# IEC 62304 — Activity-Level Gap Analysis
# ---------------------------------------------------------------------------

class TestIEC62304ActivityLevel:

    def test_list_activity_ids_returns_strings(self, class_ii_device):
        val = IEC62304LifecycleValidator(class_ii_device)
        ids = val.list_activity_ids()
        assert len(ids) > 0
        assert all(": " in aid for aid in ids)  # format: "{section}: {activity}"

    def test_activity_level_gap_analysis_all_done(self, class_ii_device):
        val = IEC62304LifecycleValidator(class_ii_device)
        all_ids = val.list_activity_ids()
        result = val.gap_analysis(completed_activity_ids=all_ids)
        assert result["Gaps"] == 0
        assert result["Completed"] == result["Total Required Activities"]

    def test_activity_level_gap_analysis_partial(self, class_ii_device):
        val = IEC62304LifecycleValidator(class_ii_device)
        all_ids = val.list_activity_ids()
        # Mark only the first activity as complete
        result = val.gap_analysis(completed_activity_ids=[all_ids[0]])
        assert result["Completed"] == 1
        assert result["Gaps"] == result["Total Required Activities"] - 1

    def test_activity_level_catches_partial_section(self, class_iii_device):
        """Section-level analysis would miss a partially-done section; activity-level catches it."""
        val = IEC62304LifecycleValidator(class_iii_device)
        all_ids = val.list_activity_ids()
        # Find two activities from the same section
        from collections import defaultdict
        by_section = defaultdict(list)
        for aid in all_ids:
            section = aid.split(": ")[0]
            by_section[section].append(aid)
        multi_act_sections = {s: acts for s, acts in by_section.items() if len(acts) > 1}
        assert multi_act_sections, "No multi-activity section found to test with"

        section, acts = next(iter(multi_act_sections.items()))
        # Mark only the first activity in that section as done
        result_activity = val.gap_analysis(completed_activity_ids=[acts[0]])
        # Section-level marks entire section done
        result_section = val.gap_analysis(completed_sections=[section])
        # Activity-level should see more gaps than section-level
        assert result_activity["Gaps"] > result_section["Gaps"]

    def test_gap_analysis_section_level_still_works(self, class_ii_device):
        """Backwards compatibility: section-level still works unchanged."""
        val = IEC62304LifecycleValidator(class_ii_device)
        required = val.required_activities()
        all_sections = list(set(a.section for a in required))
        result = val.gap_analysis(completed_sections=all_sections)
        assert result["Gaps"] == 0

    def test_describe_item_selection_covers_all_activities(self, class_ii_device):
        val = IEC62304LifecycleValidator(class_ii_device)
        selection = val.describe_item_selection()
        assert len(selection) == len(val.LIFECYCLE_ACTIVITIES)
        assert all("Required for This Device" in item for item in selection)
        assert all("Reason" in item for item in selection)


# ---------------------------------------------------------------------------
# IMDRF — Confidence Score & Manual Verification Flag
# ---------------------------------------------------------------------------

class TestIMDRFConfidence:

    def test_explicit_categorize_has_full_confidence(self):
        from samd_toolkit.standards.imdrf import IMDRFCategorizer, HealthcareState, SignificanceOfOutput
        cat = IMDRFCategorizer().categorize(
            HealthcareState.CRITICAL, SignificanceOfOutput.TREAT_OR_DIAGNOSE
        )
        assert cat.confidence == 1.0
        assert cat.verify_manually is False

    def test_heuristic_no_keywords_low_confidence(self):
        from samd_toolkit.standards.imdrf import IMDRFCategorizer
        cat = IMDRFCategorizer().categorize_from_description(
            intended_use="Helps users track their general health",
            condition_severity="non-serious",
        )
        assert cat.confidence < 0.80
        assert cat.verify_manually is True
        assert cat.confidence_note != ""

    def test_heuristic_strong_treat_keywords_higher_confidence(self):
        from samd_toolkit.standards.imdrf import IMDRFCategorizer
        cat = IMDRFCategorizer().categorize_from_description(
            intended_use="Autonomous closed-loop insulin delivery — treats and administers dose",
            is_autonomous=True,
            condition_severity="critical",
        )
        assert cat.confidence >= 0.80
        assert cat.verify_manually is False

    def test_heuristic_drive_keywords_medium_confidence(self):
        from samd_toolkit.standards.imdrf import IMDRFCategorizer
        cat = IMDRFCategorizer().categorize_from_description(
            intended_use="Detects and alerts clinicians to arrhythmia events",
            condition_severity="serious",
        )
        assert 0.50 < cat.confidence < 1.0
        assert cat.category in (2, 3)  # drive + serious → Category II or III

    def test_heuristic_confidence_note_populated(self):
        from samd_toolkit.standards.imdrf import IMDRFCategorizer
        cat = IMDRFCategorizer().categorize_from_description(
            intended_use="recommends treatment plan",
            condition_severity="critical",
        )
        assert len(cat.confidence_note) > 0

    def test_str_output_includes_confidence(self):
        from samd_toolkit.standards.imdrf import IMDRFCategorizer, HealthcareState, SignificanceOfOutput
        cat = IMDRFCategorizer().categorize(
            HealthcareState.SERIOUS, SignificanceOfOutput.DRIVE_MANAGEMENT
        )
        output = str(cat)
        assert "Confidence" in output
        assert "100%" in output
