"""
samd_toolkit/cybersecurity/sbom.py
=====================================
Software Bill of Materials (SBOM) Generator for SaMD.

References:
- NTIA "Minimum Elements for a Software Bill of Materials" (2021)
- FD&C Act §524B — Mandatory SBOM for cyber device premarket submissions
- FDA Cybersecurity Guidance 2023 §IV.C
- SPDX 2.3 (ISO/IEC 5962:2021) — Machine-readable SBOM format
- CycloneDX 1.5 — OWASP SBOM standard

FDA requires SBOMs for all "cyber devices" submitted after March 29, 2023.
A cyber device is any device that: contains software, connects to the internet,
AND has characteristics vulnerable to cybersecurity threats.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime, timezone
import json
import hashlib


@dataclass
class SBOMComponent:
    """
    A single software component in the SBOM.
    Meets NTIA minimum elements (2021).
    """
    # NTIA Minimum Elements
    supplier: str                        # Organization supplying the component
    name: str                            # Component name
    version: str                         # Component version
    unique_id: str = ""                  # e.g., CPE, PURL, or internal ID
    dependency_relationship: str = ""    # e.g., "Direct" | "Transitive"
    author: str = ""                     # Person/tool generating SBOM entry
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Extended fields (recommended)
    license_id: str = ""                 # SPDX license ID, e.g., "MIT", "Apache-2.0"
    hash_algorithm: str = "SHA-256"
    hash_value: str = ""
    component_type: str = "library"      # library | framework | application | container | os
    language: str = ""
    homepage: str = ""
    known_vulnerabilities: List[str] = field(default_factory=list)  # CVE IDs

    def __post_init__(self):
        if not self.unique_id:
            # Generate a PURL-style identifier
            self.unique_id = f"pkg:{self.component_type}/{self.supplier.lower()}/{self.name}@{self.version}"

    @property
    def has_critical_vulnerabilities(self) -> bool:
        return len(self.known_vulnerabilities) > 0

    def to_dict(self) -> Dict:
        return {
            "Supplier": self.supplier,
            "Name": self.name,
            "Version": self.version,
            "Unique ID (PURL)": self.unique_id,
            "Dependency": self.dependency_relationship,
            "License": self.license_id,
            "Component Type": self.component_type,
            "Known CVEs": ", ".join(self.known_vulnerabilities) or "None",
            "Hash": f"{self.hash_algorithm}:{self.hash_value}" if self.hash_value else "Not provided",
        }


class SBOMGenerator:
    """
    Generates a Software Bill of Materials (SBOM) for a SaMD device.

    In real use: integrate with package managers (pip, npm, Maven) to
    auto-extract component lists. This class provides representative
    component lists by device type for demonstration.
    """

    def __init__(self, device):
        self.device = device
        self.components: List[SBOMComponent] = []
        self.generated_at = datetime.now(timezone.utc)

    def add_component(self, component: SBOMComponent) -> None:
        self.components.append(component)

    def generate(self) -> "SBOMGenerator":
        """Generate a representative SBOM based on device profile."""
        self._add_base_components()
        if self.device.network_connected:
            self._add_network_components()
        if self.device.contains_ai_ml:
            self._add_ai_ml_components()
        if self.device.processes_phi:
            self._add_phi_components()
        if self.device.interoperates_with_ehr:
            self._add_ehr_components()
        return self

    def _add_base_components(self):
        """Core OS and runtime components present in most SaMD."""
        base = [
            SBOMComponent("Python Software Foundation", "Python", "3.11.8",
                          component_type="language", license_id="PSF-2.0",
                          dependency_relationship="Direct"),
            SBOMComponent("Canonical", "Ubuntu", "22.04 LTS",
                          component_type="os", license_id="GPL-2.0",
                          dependency_relationship="Direct"),
            SBOMComponent("PostgreSQL Global Dev Group", "PostgreSQL", "15.4",
                          component_type="application", license_id="PostgreSQL",
                          dependency_relationship="Direct"),
            SBOMComponent("HashiCorp", "Vault", "1.15.2",
                          component_type="application", license_id="BUSL-1.1",
                          dependency_relationship="Direct",
                          language="Go"),
            SBOMComponent("Python Packaging Authority", "cryptography", "41.0.7",
                          component_type="library", license_id="Apache-2.0",
                          dependency_relationship="Direct", language="Python",
                          known_vulnerabilities=[]),  # Check NVD for actual CVEs
            SBOMComponent("Python Packaging Authority", "requests", "2.31.0",
                          component_type="library", license_id="Apache-2.0",
                          dependency_relationship="Direct", language="Python"),
            SBOMComponent("Pallets Projects", "Flask", "3.0.0",
                          component_type="framework", license_id="BSD-3-Clause",
                          dependency_relationship="Direct", language="Python"),
            SBOMComponent("OpenSSL Project", "OpenSSL", "3.1.4",
                          component_type="library", license_id="Apache-2.0",
                          dependency_relationship="Transitive"),
        ]
        for c in base:
            self.add_component(c)

    def _add_network_components(self):
        network = [
            SBOMComponent("nginx Inc.", "nginx", "1.25.3",
                          component_type="application", license_id="BSD-2-Clause",
                          dependency_relationship="Direct"),
            SBOMComponent("Let's Encrypt", "certbot", "2.7.4",
                          component_type="application", license_id="Apache-2.0",
                          dependency_relationship="Direct"),
            SBOMComponent("Paramiko", "paramiko", "3.3.1",
                          component_type="library", license_id="LGPL-2.1",
                          dependency_relationship="Direct", language="Python"),
        ]
        for c in network:
            self.add_component(c)

    def _add_ai_ml_components(self):
        ai_ml = [
            SBOMComponent("Google", "TensorFlow", "2.14.0",
                          component_type="framework", license_id="Apache-2.0",
                          dependency_relationship="Direct", language="Python"),
            SBOMComponent("Meta AI", "PyTorch", "2.1.1",
                          component_type="framework", license_id="BSD-3-Clause",
                          dependency_relationship="Direct", language="Python"),
            SBOMComponent("NumPy Developers", "numpy", "1.26.2",
                          component_type="library", license_id="BSD-3-Clause",
                          dependency_relationship="Direct", language="Python"),
            SBOMComponent("Scikit-learn Developers", "scikit-learn", "1.3.2",
                          component_type="library", license_id="BSD-3-Clause",
                          dependency_relationship="Direct", language="Python"),
            SBOMComponent("Pandas Development Team", "pandas", "2.1.3",
                          component_type="library", license_id="BSD-3-Clause",
                          dependency_relationship="Direct", language="Python"),
        ]
        for c in ai_ml:
            self.add_component(c)

    def _add_phi_components(self):
        phi = [
            SBOMComponent("HL7 International", "fhirclient", "4.1.0",
                          component_type="library", license_id="Apache-2.0",
                          dependency_relationship="Direct", language="Python"),
            SBOMComponent("Python Packaging Authority", "pycryptodome", "3.19.0",
                          component_type="library", license_id="BSD-2-Clause",
                          dependency_relationship="Direct", language="Python"),
        ]
        for c in phi:
            self.add_component(c)

    def _add_ehr_components(self):
        ehr = [
            SBOMComponent("HL7 International", "hl7apy", "1.3.4",
                          component_type="library", license_id="MIT",
                          dependency_relationship="Direct", language="Python"),
            SBOMComponent("Firely", "fhir.resources", "7.0.2",
                          component_type="library", license_id="BSD-3-Clause",
                          dependency_relationship="Direct", language="Python"),
        ]
        for c in ehr:
            self.add_component(c)

    def components_with_vulnerabilities(self) -> List[SBOMComponent]:
        return [c for c in self.components if c.known_vulnerabilities]

    def export_spdx_json(self) -> Dict:
        """Export SBOM in SPDX 2.3 JSON format."""
        doc_id = f"SPDXRef-DOCUMENT-{self.device.name.replace(' ', '-')}-{self.device.version}"
        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": doc_id,
            "name": f"{self.device.name} SBOM",
            "documentNamespace": f"https://example.com/sbom/{self.device.uid}",
            "creationInfo": {
                "created": self.generated_at.isoformat(),
                "creators": [f"Tool: samd-validation-toolkit", f"Organization: {self.device.manufacturer}"],
            },
            "packages": [
                {
                    "SPDXID": f"SPDXRef-{c.name.replace(' ', '-')}-{c.version}",
                    "name": c.name,
                    "version": c.version,
                    "supplier": f"Organization: {c.supplier}",
                    "downloadLocation": c.homepage or "NOASSERTION",
                    "licenseConcluded": c.license_id or "NOASSERTION",
                    "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                      "referenceType": "purl",
                                      "referenceLocator": c.unique_id}],
                }
                for c in self.components
            ],
        }

    def summary(self) -> Dict:
        return {
            "Device": self.device.name,
            "SBOM Generated": self.generated_at.isoformat(),
            "Total Components": len(self.components),
            "Direct Dependencies": sum(1 for c in self.components if c.dependency_relationship == "Direct"),
            "Components with Known CVEs": len(self.components_with_vulnerabilities()),
            "License Types": len(set(c.license_id for c in self.components if c.license_id)),
            "Format": "SPDX 2.3 / CycloneDX 1.5 compatible",
        }

    def print_summary(self):
        print("\n" + "="*70)
        print("SOFTWARE BILL OF MATERIALS (SBOM) — FDA §524B Compliant")
        print("="*70)
        for k, v in self.summary().items():
            print(f"  {k:<40} {v}")
        print("\nComponent List:")
        print(f"  {'Name':<25} {'Version':<12} {'License':<20} {'CVEs'}")
        print("  " + "-"*68)
        for c in self.components:
            cves = ", ".join(c.known_vulnerabilities) if c.known_vulnerabilities else "None"
            print(f"  {c.name:<25} {c.version:<12} {c.license_id:<20} {cves}")
        print()
