from datetime import datetime

from pydantic import BaseModel, Field


class RuleResult(BaseModel):
    """What a single rule returns after checking a URL."""

    name: str
    triggered: bool
    weight: int
    score_contribution: int  # 0 when not triggered, otherwise equals weight
    explanation: str


class ScanResult(BaseModel):
    """Full result of scanning a URL — score, verdict, and per-rule breakdown."""

    id: str
    url: str
    verdict: str  # "phishy" or "not_phishy"
    score: float = Field(ge=0, le=100)
    threshold: int
    rules: list[RuleResult]
    created_at: datetime


class ScanRequest(BaseModel):
    """Request body for single URL scan."""

    url: str = Field(min_length=1, max_length=2048)
