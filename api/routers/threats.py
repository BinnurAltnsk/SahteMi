from fastapi import APIRouter

from api.db.session import get_session_factory
from api.tools.url_intel import get_threat_stats

router = APIRouter(prefix="/api/v1/threats", tags=["threats"])


@router.get("/stats")
async def threat_stats() -> dict[str, int | str]:
    """Veritabanındaki güncel tehdit istihbaratı kayıt sayılarını döndürür."""
    try:
        factory = get_session_factory()
        async with factory() as session:
            return await get_threat_stats(session)
    except Exception:  # noqa: BLE001
        return {"status": "db_unavailable", "total": 0}
