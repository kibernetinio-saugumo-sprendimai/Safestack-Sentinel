from dataclasses import asdict, dataclass
from typing import Any, Dict, List


@dataclass
class Finding:
    check: str
    severity: str
    status: str
    summary: str
    evidence: Any = None
    remediation: str = ""
    command: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def score(findings: List[Finding]) -> int:
    deductions = {"critical": 35, "high": 20, "medium": 10, "low": 3}
    return max(0, 100 - sum(deductions.get(f.severity, 0)
                             for f in findings if f.status == "fail"))
