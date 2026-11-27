"""SahteMi FastAPI servisi ile iletişim kuran asenkron HTTP istemcisi."""

from __future__ import annotations

import httpx

from api.schemas.analyze import AnalyzeResponse, Channel


class ApiClientError(Exception):
    """SahteMi API isteği başarısız olduğunda fırlatılır."""


class SahteMiApiClient:
    """FastAPI gateway üzerinden analiz ve istatistik uç noktalarını çağırır."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        *,
        timeout: float = 15.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._transport = transport

    def _build_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            transport=self._transport,
        )

    async def analyze(self, text: str, *, channel: Channel = Channel.OTHER) -> AnalyzeResponse:
        """Mesaj veya URL'yi `/api/v1/analyze` uç noktasına gönderir."""
        payload = {"text": text, "channel": channel.value}
        try:
            async with self._build_client() as client:
                response = await client.post("/api/v1/analyze", json=payload)
                response.raise_for_status()
                return AnalyzeResponse.model_validate(response.json())
        except httpx.TimeoutException as exc:
            raise ApiClientError("Analiz servisi zaman aşımına uğradı.") from exc
        except httpx.HTTPStatusError as exc:
            raise ApiClientError(
                f"Analiz servisi hata döndürdü (HTTP {exc.response.status_code})."
            ) from exc
        except httpx.HTTPError as exc:
            raise ApiClientError("Analiz servisine bağlanılamadı.") from exc

    async def get_threat_stats(self) -> dict[str, int | str]:
        """Tehdit istihbaratı veritabanı özetini `/api/v1/threats/stats` üzerinden alır."""
        try:
            async with self._build_client() as client:
                response = await client.get("/api/v1/threats/stats")
                response.raise_for_status()
                data = response.json()
                if not isinstance(data, dict):
                    raise ApiClientError("İstatistik yanıtı beklenmeyen biçimde.")
                return data
        except httpx.TimeoutException as exc:
            raise ApiClientError("İstatistik servisi zaman aşımına uğradı.") from exc
        except httpx.HTTPStatusError as exc:
            raise ApiClientError(
                f"İstatistik servisi hata döndürdü (HTTP {exc.response.status_code})."
            ) from exc
        except httpx.HTTPError as exc:
            raise ApiClientError("İstatistik servisine bağlanılamadı.") from exc
