# 🏥 SaMD Validation Toolkit

> **Software as a Medical Device (SaMD) Validation Checklist & IQ/OQ/PQ Template Generator**
> Covering FDA 21 CFR Part 11/820, IEC 62304, IEC 62443, ISO 14971, IMDRF, EU MDR 2017/745

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![FDA 21 CFR 820](https://img.shields.io/badge/FDA-21%20CFR%20820-red.svg)]()
[![IEC 62304](https://img.shields.io/badge/IEC-62304-green.svg)]()
[![ISO 14971](https://img.shields.io/badge/ISO-14971-orange.svg)]()

---

## 📋 Overview

The **SaMD Validation Toolkit** is a Python-based framework for generating, managing, and executing validation protocols for Software as a Medical Device (SaMD). It produces audit-ready IQ/OQ/PQ documentation, risk-classified checklists, and cybersecurity compliance reports aligned with both **US FDA** and **international** regulatory standards.

### Who This Is For

| Role | Use Case |
|------|----------|
| **Regulatory Affairs (RA)** | Generate 510(k), De Novo, PMA-ready validation packages |
| **Quality Management (QMS)** | Maintain IEC 62304 software lifecycle documentation |
| **DevOps/MLOps** | Automate SaMD CI/CD validation gates |
| **Cybersecurity Teams** | Run IEC 62443 / IMDRF cybersecurity checklists |
| **Clinical Engineers** | Verify device software meets intended use requirements |

---

## 🔬 Supported Device Classes & Real-World Examples

### FDA Class I (General Controls)
- **Fitbit / Apple Watch** — Activity tracking (non-clinical wellness)
- **Basic EHR viewers** — Non-diagnostic record display
- **Inventory management software** — Hospital asset tracking

### FDA Class II (Special Controls + 510(k))
- **iRhythm Zio Patch** — Cardiac arrhythmia monitoring (AI-driven ECG)
- **Dario Blood Glucose Meter** — Continuous glucose monitoring companion app
- **Philips IntelliSpace** — Radiology PACS/diagnostic imaging software
- **Veracyte Genomic Classifier** — Oncology decision support

### FDA Class III (PMA — Highest Risk)
- **Abbott FreeStyle Libre** — Closed-loop insulin dosing (AID systems)
- **Medtronic CareLink** — Implantable cardiac device remote monitoring
- **Viz.ai** — AI stroke detection / LVO notification (FDA De Novo cleared)
- **IDx-DR (Digital Diagnostics)** — Autonomous AI diabetic retinopathy detection

---

## 📐 Regulatory Standards Covered

### United States (FDA)
| Standard | Scope |
|----------|-------|
| 21 CFR Part 820 | Quality System Regulation (QSR) |
| 21 CFR Part 11 | Electronic Records & Signatures |
| FDA SaMD Guidance (2019) | Software Functions, Clinical Decision Support |
| FDA AI/ML Action Plan (2021) | Predetermined Change Control Plans |
| FDA Cybersecurity Guidance (2023) | Premarket/Postmarket Cyber Requirements |

### International
| Standard | Scope |
|----------|-------|
| IEC 62304:2006+AMD1:2015 | Medical Device Software Lifecycle |
| IEC 62443 | Industrial Cybersecurity (adopted for SaMD) |
| ISO 14971:2019 | Risk Management for Medical Devices |
| ISO 13485:2016 | Quality Management Systems |
| IMDRF SaMD N10/N12/N23 | SaMD Framework & Risk Categorization |
| EU MDR 2017/745 | European Medical Device Regulation |
| IEC 82304-1 | Health Software General Requirements |

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourorg/samd-validation-toolkit.git
cd samd-validation-toolkit

# Install dependencies
pip install -r requirements.txt

# Run the interactive CLI
python -m samd_toolkit

# Generate a full IQ/OQ/PQ package for a Class II device
python -m samd_toolkit generate \
  --device-class II \
  --standard iec62304 \
  --output-format pdf \
  --include-cybersecurity \
  --output ./validation_package/
```

---

## 🏗️ Architecture

```
samd-validation-toolkit/
├── samd_toolkit/
│   ├── __main__.py              # CLI entry point
│   ├── core.py                  # SaMDDevice & ValidationSession models
│   ├── validators/
│   │   ├── checklist.py         # Risk-classified validation checklists
│   │   ├── iq_oq_pq.py          # IQ/OQ/PQ protocol generator
│   │   └── lifecycle.py         # IEC 62304 software lifecycle validator
│   ├── standards/
│   │   ├── fda.py               # FDA 21 CFR 820/11, SaMD guidance
│   │   ├── iec62304.py          # IEC 62304 software safety classes
│   │   ├── iso14971.py          # ISO 14971 risk management
│   │   └── imdrf.py             # IMDRF SaMD categorization
│   ├── cybersecurity/
│   │   ├── iec62443.py          # IEC 62443 controls
│   │   ├── fda_cyber.py         # FDA 2023 Cybersecurity Guidance
│   │   └── sbom.py              # Software Bill of Materials generator
│   ├── templates/
│   │   ├── iq_template.py       # Installation Qualification
│   │   ├── oq_template.py       # Operational Qualification
│   │   ├── pq_template.py       # Performance Qualification
│   │   └── risk_template.py     # Risk Management File
│   └── reports/
│       ├── pdf_reporter.py      # PDF report generation
│       └── html_reporter.py     # HTML audit trail
├── tests/
│   ├── test_validators.py
│   ├── test_standards.py
│   └── test_cybersecurity.py
├── examples/
│   ├── class_i_wellness_app.py
│   ├── class_ii_ecg_monitor.py
│   └── class_iii_closed_loop_insulin.py
├── docs/
│   ├── regulatory_mapping.md
│   └── cybersecurity_framework.md
├── requirements.txt
└── setup.py
```

---

## 📦 Installation

### From PyPI (when published)
```bash
pip install samd-validation-toolkit
```

### Development Install
```bash
git clone https://github.com/yourorg/samd-validation-toolkit.git
cd samd-validation-toolkit
pip install -e ".[dev]"
```

### Requirements
- Python 3.9+
- See `requirements.txt` for full dependency list

---

## 💻 Usage Examples

### 1. Generate IQ/OQ/PQ for a Class II ECG Monitor

```python
from samd_toolkit.core import SaMDDevice, DeviceClass
from samd_toolkit.validators.iq_oq_pq import IQOQPQGenerator
from samd_toolkit.standards.iec62304 import SoftwareSafetyClass

device = SaMDDevice(
    name="CardioWatch AI",
    version="2.1.0",
    device_class=DeviceClass.CLASS_II,
    software_safety_class=SoftwareSafetyClass.CLASS_B,
    intended_use="Cardiac arrhythmia detection via wearable ECG",
    manufacturer="MedTech Corp",
    predicate_device="iRhythm Zio AT (K192613)"
)

generator = IQOQPQGenerator(device)
package = generator.generate_full_package()
package.export_pdf("./output/cardiowatch_validation.pdf")
```

### 2. Run IMDRF Risk Categorization

```python
from samd_toolkit.standards.imdrf import IMDRFCategorizer

categorizer = IMDRFCategorizer()
category = categorizer.categorize(
    state_of_healthcare="serious",        # serious / non-serious
    significance_of_information="treat",  # treat / diagnose / drive / inform
    intended_user="hcp"                   # hcp / patient / caregiver
)
# Returns: IMDRFCategory(category='III', risk='HIGH', fda_class_equivalent='III')
```

### 3. Cybersecurity SBOM + IEC 62443 Check

```python
from samd_toolkit.cybersecurity.sbom import SBOMGenerator
from samd_toolkit.cybersecurity.fda_cyber import FDACybersecurityChecker

sbom = SBOMGenerator(device).generate()
cyber_report = FDACybersecurityChecker(device, sbom).run_checklist()
cyber_report.export_html("./output/cybersecurity_report.html")
```

### 4. ISO 14971 Risk Management File

```python
from samd_toolkit.standards.iso14971 import RiskManagementFile, RiskItem

rmf = RiskManagementFile(device)
rmf.add_risk(RiskItem(
    hazard="Algorithm misclassification of AF",
    hazardous_situation="Patient with undetected atrial fibrillation",
    harm="Stroke / delayed treatment",
    probability_before=3,    # 1-5 scale
    severity=5,
    mitigation="Clinical validation on 10,000-patient dataset; physician review required",
    probability_after=1
))
rmf.generate_report("./output/risk_management_file.pdf")
```

---

## 🔒 Cybersecurity Framework

The toolkit implements the **FDA 2023 Cybersecurity Guidance** and **IEC 62443** controls:

| Control Domain | Standards | Checks |
|---------------|-----------|--------|
| Authentication | NIST SP 800-63B, IEC 62443-3-3 | MFA, session mgmt, credential policies |
| Data Encryption | FIPS 140-2/3, TLS 1.3 | Data at rest/transit, key management |
| Software Integrity | FDA Cyber Guidance §524B | Code signing, SBOM, patch management |
| Network Security | IEC 62443-2-4 | Segmentation, firewall rules, ports |
| Audit Logging | 21 CFR Part 11.10(e) | Tamper-evident logs, access trails |
| Vulnerability Mgmt | CVE/NVD, CVSS v3.1 | Known CVE scanning, disclosure policy |
| Incident Response | NIST SP 800-61 | Response plan, FDA reportability |

---

## 📊 IQ/OQ/PQ Protocol Summary

| Protocol | Purpose | Key Activities |
|----------|---------|----------------|
| **IQ** — Installation Qualification | Verify correct installation | Environment specs, hardware check, software install, config verification |
| **OQ** — Operational Qualification | Verify functions per design | Functional testing, boundary conditions, error handling, interface testing |
| **PQ** — Performance Qualification | Verify performance in actual use | Clinical scenario testing, load/stress testing, user acceptance testing |

---

## 🌍 International Regulatory Mapping

| Jurisdiction | Pathway | Key Standard | This Toolkit |
|-------------|---------|-------------|--------------|
| USA (FDA) | 510(k) / De Novo / PMA | 21 CFR 820 + SaMD Guidance | ✅ Full support |
| European Union | CE Marking under EU MDR | IEC 62304 + ISO 14971 | ✅ Full support |
| Canada (HC) | Medical Device License | CMDR + IEC 62304 | ✅ Partial support |
| Japan (PMDA) | Ninsho/Todokede | JIRA + IEC 62304 | 🔄 In progress |
| Australia (TGA) | ARTG inclusion | TGA SaMD Guidance | 🔄 In progress |

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). We welcome:
- New device class examples
- Additional regulatory standard mappings
- Cybersecurity control expansions
- Report template improvements

---

## ⚠️ Disclaimer

**This toolkit generates templates — it is not a validated Quality Management System (QMS).**

| What this toolkit does | What this toolkit does NOT do |
|---|---|
| Generates IQ/OQ/PQ protocol templates | Execute or sign off a regulated validation |
| Pre-populates risk items per ISO 14971 | Replace a Risk Management File approved by a QE |
| Produces SBOM drafts in SPDX 2.3 format | Submit a §524B-compliant SBOM to the FDA |
| Outputs HTML audit-trail reports | Store records in a 21 CFR Part 11-compliant system |

**Before using any output for a regulatory submission**, all generated documents must be:

1. Reviewed and approved by a qualified Regulatory Affairs professional
2. Executed and stored within a **21 CFR Part 11-compliant QMS** (e.g., Veeva Vault, MasterControl, Greenlight Guru, or equivalent)
3. Subject to your organisation's change control, CAPA, and document control procedures

This toolkit does **not** constitute regulatory advice. The authors assume no liability for regulatory decisions made using this software. Always consult a qualified RA professional for FDA submissions, CE marking, or other regulatory approvals.

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

*Built for the global SaMD community — RA professionals, QMS engineers, clinical software developers.*
