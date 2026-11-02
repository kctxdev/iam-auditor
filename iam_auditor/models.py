from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # menor = pior
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Finding:
    code: str
    severity: str
    category: str  # policy | trust | credentials | unused | hygiene | access-analyzer
    resource_type: str
    resource_name: str
    arn: str
    title: str
    description: str
    recommendation: str
    evidence: dict = field(default_factory=dict)
    affected: list = field(default_factory=list)
    suggested_policy: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)
