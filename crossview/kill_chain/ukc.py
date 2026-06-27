"""Unified Kill Chain (Pols, 2017, revised 2021) — 18 phases in 3 stages.

Hardcoded because UKC is a fixed framework, not pulled from a feed.
Source: Paul Pols, "The Unified Kill Chain" (https://www.unifiedkillchain.com/).
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class UKCPhase:
    id: str
    name: str
    stage: str
    order: int
    description: str


# Three stages: In (initial foothold), Through (network propagation), Out (action on objectives)
STAGES = (
    ("UKC-IN", "Initial Foothold"),
    ("UKC-THROUGH", "Network Propagation"),
    ("UKC-OUT", "Action on Objectives"),
)


PHASES: tuple[UKCPhase, ...] = (
    # ---- IN ----
    UKCPhase("UKC-1",  "Reconnaissance",        "UKC-IN", 1,
             "Researching, identifying, and selecting targets using active or passive reconnaissance."),
    UKCPhase("UKC-2",  "Resource Development",  "UKC-IN", 2,
             "Preparing the operational environment: infrastructure, accounts, and capabilities."),
    UKCPhase("UKC-3",  "Delivery",              "UKC-IN", 3,
             "Techniques resulting in the transmission of a weaponized payload to the targeted environment."),
    UKCPhase("UKC-4",  "Social Engineering",    "UKC-IN", 4,
             "Manipulating people to perform actions or divulge confidential information."),
    UKCPhase("UKC-5",  "Exploitation",          "UKC-IN", 5,
             "Techniques to exploit vulnerabilities in systems that may result in code execution."),
    UKCPhase("UKC-6",  "Persistence",           "UKC-IN", 6,
             "Mechanisms to maintain access across system restarts, credential changes, and other interruptions."),
    UKCPhase("UKC-7",  "Defense Evasion",       "UKC-IN", 7,
             "Techniques used by adversaries to avoid detection throughout their compromise."),
    UKCPhase("UKC-8",  "Command & Control",     "UKC-IN", 8,
             "Techniques to communicate with controlled systems within a target network."),
    # ---- THROUGH ----
    UKCPhase("UKC-9",  "Pivoting",              "UKC-THROUGH", 9,
             "Tunneling traffic through a controlled system to other systems not directly accessible."),
    UKCPhase("UKC-10", "Discovery",             "UKC-THROUGH", 10,
             "Techniques that allow adversaries to gain knowledge about the system and internal network."),
    UKCPhase("UKC-11", "Privilege Escalation",  "UKC-THROUGH", 11,
             "Techniques that allow adversaries to obtain higher-level permissions on a system or network."),
    UKCPhase("UKC-12", "Execution",             "UKC-THROUGH", 12,
             "Techniques that result in adversary-controlled code running on a local or remote system."),
    UKCPhase("UKC-13", "Credential Access",     "UKC-THROUGH", 13,
             "Techniques for stealing credentials like account names and passwords."),
    UKCPhase("UKC-14", "Lateral Movement",      "UKC-THROUGH", 14,
             "Techniques that enable an adversary to access and control remote systems on a network."),
    # ---- OUT ----
    UKCPhase("UKC-15", "Collection",            "UKC-OUT", 15,
             "Techniques used to identify and gather information from a target network prior to exfiltration."),
    UKCPhase("UKC-16", "Exfiltration",          "UKC-OUT", 16,
             "Techniques that result in the adversary stealing data from the targeted network."),
    UKCPhase("UKC-17", "Impact",                "UKC-OUT", 17,
             "Techniques that result in the disruption of availability or compromise of integrity."),
    UKCPhase("UKC-18", "Objectives",            "UKC-OUT", 18,
             "Strategic goals achieved through the operation: financial, political, military, etc."),
)


# ATT&CK Tactic short-name → UKC phase ID. Used to bridge ATT&CK techniques into UKC.
ATTACK_TACTIC_TO_UKC: dict[str, str] = {
    "reconnaissance":         "UKC-1",
    "resource-development":   "UKC-2",
    "initial-access":         "UKC-3",
    "execution":              "UKC-12",
    "persistence":            "UKC-6",
    "privilege-escalation":   "UKC-11",
    "defense-evasion":        "UKC-7",
    "credential-access":      "UKC-13",
    "discovery":              "UKC-10",
    "lateral-movement":       "UKC-14",
    "collection":             "UKC-15",
    "command-and-control":    "UKC-8",
    "exfiltration":           "UKC-16",
    "impact":                 "UKC-17",
    # ICS-specific
    "inhibit-response-function":      "UKC-17",
    "impair-process-control":         "UKC-17",
    # ATLAS-specific
    "ml-attack-staging":              "UKC-2",
    "ml-model-access":                "UKC-3",
    "exfiltration-ml":                "UKC-16",
}
