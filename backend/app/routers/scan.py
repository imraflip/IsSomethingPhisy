from fastapi import APIRouter

from app.scanner.engine import RuleEngine
from app.scanner.schemas import ScanRequest, ScanResult

router = APIRouter(prefix="/api/v1", tags=["scan"])

engine = RuleEngine()


@router.post("/scan", response_model=ScanResult)
async def scan_url(request: ScanRequest) -> ScanResult:
    """Scan a single URL for phishing signals."""
    return engine.scan(request.url)
