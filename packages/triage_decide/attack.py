"""ATT&CK narrative, not execution.

We never run an attack. We express the plausible behavioral chain a
vulnerability enables, mapped to ATT&CK, as a board-legible risk story.
This is the line between this tool and a Caldera-class emulation platform:
narrative here, authorized execution is a separate paid engagement.
"""
from __future__ import annotations

from typing import List, Tuple

# Internet-facing exploitation -> impact
PUBLIC_CHAIN: List[Tuple[str, str]] = [
    ("T1190", "Exploit Public-Facing Application"),
    ("T1059", "Command and Scripting Interpreter"),
    ("T1078", "Valid Accounts"),
    ("T1021", "Remote Services"),
    ("T1486", "Data Encrypted for Impact"),
]

# Internal / local exploitation -> impact
LOCAL_CHAIN: List[Tuple[str, str]] = [
    ("T1203", "Exploitation for Client Execution"),
    ("T1068", "Exploitation for Privilege Escalation"),
    ("T1078", "Valid Accounts"),
    ("T1486", "Data Encrypted for Impact"),
]


def narrative(internet_facing: bool) -> List[Tuple[str, str]]:
    return PUBLIC_CHAIN if internet_facing else LOCAL_CHAIN
