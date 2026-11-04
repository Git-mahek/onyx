"""findings.py - shared Finding record for the IoT scanner modules.

Every scanner module (open ports, auth_check, ...) reports results as
Finding objects so the final report can merge them.
"""

from dataclasses import dataclass


@dataclass
class Finding:
    host: str
    port: int
    service: str
    issue: str
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL
    detail: str = ""
