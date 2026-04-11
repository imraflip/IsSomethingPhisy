import uuid
from datetime import UTC, datetime

from app.config import ScannerConfig, settings
from app.scanner.rules import ALL_RULES
from app.scanner.schemas import ScanResult
from app.utils.url_parser import parse_url


class RuleEngine:
    def __init__(self, config: ScannerConfig | None = None):
        self.config = config or settings
        self.rules = ALL_RULES

    def scan(self, url: str) -> ScanResult:
        """Run all rules against a URL and return a scored verdict."""
        parsed = parse_url(url)
        results = [rule(parsed, self.config) for rule in self.rules]

        raw_score = sum(r.score_contribution for r in results)
        final_score = min(raw_score, 100.0)  # cap at 100
        verdict = "phishy" if final_score >= self.config.PHISHY_THRESHOLD else "not_phishy"

        return ScanResult(
            id=str(uuid.uuid4()),
            url=parsed.raw_url,
            verdict=verdict,
            score=final_score,
            threshold=self.config.PHISHY_THRESHOLD,
            rules=results,
            created_at=datetime.now(UTC),
        )
