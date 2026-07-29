from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class CheckResult(BaseModel):
    id: str
    title: str
    status: str  # "pass" | "warn" | "fail" | "error"
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    summary: str
    explanation: str
    fix: str
    evidence: Dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    domain: str
    scanned_at: str
    grade: str  # "A", "B", "C", "D", "F"
    score: int  # 0 to 100
    checks: List[CheckResult] = Field(default_factory=list)
    audio_briefing_url: Optional[str] = None
    cached: bool = False
