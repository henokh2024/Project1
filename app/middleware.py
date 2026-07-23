import json
import logging
import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.metrics import REQUEST_COUNT, REQUEST_LATENCY


logging.basicConfig(
    level=logging.INFO,
)

logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next,
    ):
        # perf_counter is designed for measuring elapsed time.
        start_time = time.perf_counter()

        # Save the requested path once so it can be reused
        # in both the success and exception sections.
        endpoint = request.url.path

        try:
            response = await call_next(request)

            # Prometheus histograms normally store duration in seconds.
            duration_seconds = time.perf_counter() - start_time

            # Logs are easier to read in milliseconds.
            duration_ms = duration_seconds * 1000

            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=endpoint,
                status_code=str(response.status_code),
            ).inc()

            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=endpoint,
            ).observe(duration_seconds)

            log_entry = {
                "method": request.method,
                "path": endpoint,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
            }

            logger.info(
                json.dumps(log_entry)
            )

            return response

        except Exception as error:
            duration_seconds = time.perf_counter() - start_time
            duration_ms = duration_seconds * 1000

            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=endpoint,
                status_code="500",
            ).inc()

            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=endpoint,
            ).observe(duration_seconds)

            error_log_entry = {
                "method": request.method,
                "path": endpoint,
                "status_code": 500,
                "duration_ms": round(duration_ms, 2),
                "error": str(error),
            }

            logger.exception(
                json.dumps(error_log_entry)
            )

            raise