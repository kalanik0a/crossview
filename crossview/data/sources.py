"""MITRE data source URLs. All verified reachable on first lock-in."""
from dataclasses import dataclass
from typing import Literal

SourceFormat = Literal["stix-json", "stix-zip-xml", "jsonld", "json"]


@dataclass(frozen=True)
class Source:
    key: str
    label: str
    url: str
    fmt: SourceFormat
    filename: str  # what to call it under data/raw/


SOURCES: tuple[Source, ...] = (
    Source(
        key="capec",
        label="MITRE CAPEC (STIX 2.1)",
        url="https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json",
        fmt="stix-json",
        filename="capec.stix.json",
    ),
    Source(
        key="cwe",
        label="MITRE CWE (XML, all views including 1000)",
        url="https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        fmt="stix-zip-xml",
        filename="cwec_latest.xml.zip",
    ),
    Source(
        key="attack-enterprise",
        label="MITRE ATT&CK Enterprise (STIX 2.0)",
        url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        fmt="stix-json",
        filename="attack-enterprise.json",
    ),
    Source(
        key="attack-mobile",
        label="MITRE ATT&CK Mobile (STIX 2.0)",
        url="https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        fmt="stix-json",
        filename="attack-mobile.json",
    ),
    Source(
        key="attack-ics",
        label="MITRE ATT&CK ICS (STIX 2.0)",
        url="https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
        fmt="stix-json",
        filename="attack-ics.json",
    ),
    Source(
        key="d3fend-mappings",
        label="MITRE D3FEND full mappings (JSON-LD)",
        url="https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json",
        fmt="jsonld",
        filename="d3fend-mappings.json",
    ),
    Source(
        key="d3fend-ontology",
        label="MITRE D3FEND ontology (JSON-LD)",
        url="https://d3fend.mitre.org/ontologies/d3fend.json",
        fmt="jsonld",
        filename="d3fend-ontology.json",
    ),
    Source(
        key="atlas",
        label="MITRE ATLAS (adversarial AI/ML, STIX)",
        url="https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas.json",
        fmt="stix-json",
        filename="atlas.stix.json",
    ),
)


def by_key(key: str) -> Source | None:
    for s in SOURCES:
        if s.key == key:
            return s
    return None
