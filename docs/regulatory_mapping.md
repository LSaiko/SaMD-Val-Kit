# Regulatory Mapping Reference

> SaMD Validation Toolkit — Regulatory Standards Cross-Reference

---

## United States (FDA)

### FDA Device Classification Framework

| Class | Risk Level | Pathway | % of Devices | Examples |
|-------|-----------|---------|-------------|---------|
| **Class I** | Low | Exempt or 510(k) | ~47% | Wellness trackers, EHR viewers, scheduling apps |
| **Class II** | Moderate | 510(k) or De Novo | ~43% | ECG monitors, CGM apps, PACS viewers, CDS tools |
| **Class III** | High | PMA | ~10% | AID systems, implantable device software, autonomous diagnostics |

### FDA SaMD-Specific Guidance Documents

| Guidance | Year | Key Requirements |
|----------|------|-----------------|
| **Software as a Medical Device (SaMD): Clinical Evaluation** | 2017 | Clinical evidence framework; analytical vs. clinical validation |
| **Clinical Decision Support Software** | 2022 (Final) | Distinguishes CDS that IS vs. IS NOT a device |
| **AI/ML-Based SaMD Action Plan** | 2021 | PCCP (Predetermined Change Control Plans); total product lifecycle |
| **Cybersecurity in Medical Devices** | 2023 (Final) | Replaces 2014/2018; §524B mandatory SBOM, CVD, patch plan |
| **Content of Premarket Submissions for Device Software Functions** | 2023 | Level of Concern → Software Documentation Level mapping |
| **General Wellness: Policy for Low Risk Devices** | 2016 | Safe harbor for wellness/fitness software |
| **Enforcement Policy for Digital Health Devices (COVID)** | 2020 | Emergency enforcement discretion |

### 21 CFR Regulatory Citations

| Regulation | Topic | Key Sections |
|-----------|-------|-------------|
| **21 CFR Part 820** | Quality System Regulation (QSR) | §820.30 Design Controls; §820.70 Production Controls; §820.75 Process Validation |
| **21 CFR Part 11** | Electronic Records/Signatures | §11.10 Controls for closed systems; §11.50 Signature manifestations |
| **21 CFR Part 803** | Medical Device Reporting (MDR) | Death/serious injury reporting; 30-day/5-day reports |
| **21 CFR Part 806** | Corrections and Removals | Recall/correction reporting thresholds |
| **21 CFR Part 807** | Establishment Registration and Device Listing | Premarket notification (510(k)) |
| **21 CFR Part 814** | Premarket Approval (PMA) | §814.20 PMA application content |
| **21 CFR Part 812** | Investigational Device Exemption (IDE) | Clinical study requirements for Class III |
| **21 CFR Part 801** | Labeling | General labeling requirements |
| **FD&C Act §524B** | Cybersecurity for Cyber Devices | Mandatory SBOM; CVD; patch plan; post-market monitoring |

---

## International Standards

### IEC 62304 — Software Safety Class Requirements Matrix

| Requirement | Class A | Class B | Class C |
|-------------|:-------:|:-------:|:-------:|
| Software Development Plan | ✅ | ✅ | ✅ |
| Software Requirements Spec | ✅ | ✅ | ✅ |
| Software Architecture | ❌ | ✅ | ✅ |
| Detailed Design | ❌ | ❌ | ✅ |
| Unit Implementation + Verification | ❌ | ❌ | ✅ |
| Integration Testing | ❌ | ✅ | ✅ |
| System Testing | ✅ | ✅ | ✅ |
| Software Risk Management | ❌ | ✅ | ✅ |
| SOUP Anomaly List | ❌ | ❌ | ✅ |
| Configuration Management | ✅ | ✅ | ✅ |

**Real-world Class Assignments:**
- **Class A:** Hospital scheduling, billing, administrative EMR modules
- **Class B:** Blood pressure monitoring, non-diagnostic ECG viewer, nurse call systems, radiology PACS (viewing only)
- **Class C:** Closed-loop drug delivery, ventilator control, radiation therapy planning, autonomous AI diagnosis (Class III SaMD)

### IMDRF Risk Categorization Matrix

```
                        SIGNIFICANCE OF SaMD INFORMATION
                  ┌────────────────┬────────────────┬────────────────┐
                  │ Treat/Diagnose │  Drive Mgmt    │  Inform Mgmt   │
┌─────────────────┼────────────────┼────────────────┼────────────────┤
│ CRITICAL        │  Category IV   │  Category III  │  Category II   │
├─────────────────┼────────────────┼────────────────┼────────────────┤
│ SERIOUS         │  Category III  │  Category II   │  Category II   │
├─────────────────┼────────────────┼────────────────┼────────────────┤
│ NON-SERIOUS     │  Category II   │  Category I    │  Category I    │
└─────────────────┴────────────────┴────────────────┴────────────────┘
```

**Category Clinical Evidence Requirements (IMDRF N23):**

| Category | Analytical Validation | Clinical Validation | Level of Evidence |
|----------|:---------------------:|:-------------------:|-------------------|
| I | Required | May not be required | Bench testing; literature |
| II | Required | Required (some) | Observational study; literature |
| III | Required | Required | Well-controlled clinical study |
| IV | Required | Required | Randomized Controlled Trial (preferred) |

### ISO 14971 Risk Acceptability Matrix (5×5 ALARP)

```
         SEVERITY →
         1-Negligible  2-Minor  3-Serious  4-Critical  5-Catastrophic
P  1-Improbable   [  A  ]    [  A  ]    [  A  ]    [ ALARP ]   [ ALARP ]
R  2-Remote       [  A  ]    [  A  ]    [ ALARP ]   [ ALARP ]   [  U*  ]
O  3-Occasional   [  A  ]    [ ALARP ]  [ ALARP ]   [  U*  ]    [  U*  ]
B  4-Probable     [ ALARP ]  [ ALARP ]  [  U*  ]    [  U*  ]    [  U*  ]
   5-Frequent     [ ALARP ]  [  U*  ]   [  U*  ]    [  U*  ]    [  U*  ]

A = Acceptable | ALARP = As Low As Reasonably Practicable | U* = Unacceptable
```

---

## European Union (EU MDR 2017/745)

### EU MDR Classification Rules for SaMD

| Rule | Scope | Class |
|------|-------|-------|
| **Rule 11** | Software intended to provide information for decisions with diagnosis/treatment implications | IIa, IIb, or III depending on impact |
| **Rule 11 (serious/life-threatening)** | Software intended to provide information for decisions where errors could cause death/irreversible harm | III |
| **Rule 22** | Software specifically intended to control, monitor, or directly influence Class IIb/III devices | III |

**EU MDR Rule 11 Decision Logic:**
- Serious / life-threatening impact → **Class III**
- Serious deterioration / surgical intervention required → **Class IIb**  
- Other diagnosis/treatment decisions → **Class IIa**
- All other software → **Class I**

### EU MDR Technical Documentation Requirements (Annex II/III)

- Device description and specification (including SOUP/component list)
- Reference to previous generations and similar devices
- Design and manufacturing information (including software architecture)
- General Safety and Performance Requirements (GSPR) compliance
- Benefit-risk analysis and risk management (ISO 14971)
- Product verification and validation (including clinical evaluation)
- Post-market surveillance plan
- Clinical evaluation report (CER)

---

## Cybersecurity Standards Mapping

| Domain | US Standard | International Standard | Toolkit Module |
|--------|------------|----------------------|---------------|
| Overall Framework | FDA Cyber 2023 + FD&C §524B | IEC 62443 series | `cybersecurity/fda_cyber.py` |
| Secure Development | NIST SP 800-218 (SSDF) | IEC 62443-4-1 | `CY-AR-006` |
| Authentication | NIST SP 800-63B | IEC 62443-3-3 SR 1.1 | `CY-AR-001` |
| Cryptography | FIPS 140-3 | ISO/IEC 19790 | `CY-AR-002` |
| Vulnerability Mgmt | CISA KEV Catalog | ISO/IEC 30111, 29147 | `CY-TS-002` |
| SBOM | NTIA Minimum Elements | SPDX 2.3 / CycloneDX 1.5 | `cybersecurity/sbom.py` |
| Incident Response | NIST SP 800-61 | ISO/IEC 27035 | `CY-PM-002` |
| Network Security | NIST SP 800-82 | IEC 62443-3-2 | `CY-AR-004` |

---

## Real-World SaMD Product Reference Table

| Device | Manufacturer | Class | Pathway | Key Standards | AI/ML |
|--------|-------------|-------|---------|---------------|-------|
| Zio AT | iRhythm | II | 510(k) K192613 | IEC 62304-B; ISO 14971 | ✅ ECG AF detection |
| KardiaMobile 6L | AliveCor | II | 510(k) K200010 | IEC 62304-B | ✅ ECG analysis |
| Apple Watch ECG | Apple | II | 510(k) K182074 | IEC 62304-B | ✅ AF detection |
| Omnipod 5 | Insulet | III | PMA P200010 | IEC 62304-C; ISO 14971 | ✅ Adaptive dosing |
| Control-IQ | Tandem | III | PMA P180008 | IEC 62304-C | ✅ Closed-loop |
| MiniMed 780G | Medtronic | III | PMA P910014/S103 | IEC 62304-C | ✅ AID algorithm |
| Viz.ai LVO | Viz.ai | II | De Novo DEN180044 | IEC 62304-B | ✅ CT stroke detection |
| IDx-DR | Digital Dx | II | De Novo DEN180001 | IEC 62304-B | ✅ Autonomous retinopathy |
| IntelliSpace | Philips | II | 510(k) | IEC 62304-B | Partial |
| FreeStyle Libre 3 | Abbott | III (system) | PMA P180050 | IEC 62304-C | ✅ CGM + dosing |
| CareLink | Medtronic | II/III | Various | IEC 62304 | ✅ Remote monitoring |

---

## IQ/OQ/PQ Reference by Validation Phase

| Phase | GAMP 5 Mapping | IEC 62304 Section | FDA Reference |
|-------|---------------|------------------|---------------|
| **IQ** (Installation) | GAMP 5 Appendix M2 | §5.8.1 Software Release | 21 CFR 820.70(i) |
| **OQ** (Operational) | GAMP 5 §5.3 | §5.6 Integration Testing, §5.7 System Testing | 21 CFR 820.75 Process Validation |
| **PQ** (Performance) | GAMP 5 §5.4 | §5.7 Software System Testing | 21 CFR 820.75; FDA SaMD Guidance §V |

---

*This document is maintained as part of the SaMD Validation Toolkit. Standards evolve — always verify against current published versions.*
