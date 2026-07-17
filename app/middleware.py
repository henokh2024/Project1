import json
import logging
import time

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware


# Configure Python logging to display informational messages,
# warnings, and errors in the terminal.
logging.basicConfig(
    level=logging.INFO,
)


# Create a logger specifically for this Python module.
logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next,
    ):
        # Record the time when the request first enters the application.
        start_time = time.time()

        try:
            # Send the request to the appropriate FastAPI route
            # and wait for the route to return a response.
            response = await call_next(request)

            # Calculate how long the request took.
            # time.time() returns seconds, so we multiply by 1000
            # to convert the result into milliseconds.
            duration_ms = (
                time.time() - start_time
            ) * 1000

            # Create a structured dictionary containing
            # useful information about the completed request.
            log_entry = {
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
            }

            # Convert the dictionary into JSON and write it
            # to the application logs.
            logger.info(
                json.dumps(log_entry)
            )

            # Return the route's response to the client.
            return response

        except Exception as error:
            # Calculate how long the request ran before failing.
            duration_ms = (
                time.time() - start_time
            ) * 1000

            # Create a structured error log.
            error_log_entry = {
                "method": request.method,
                "path": request.url.path,
                "status_code": 500,
                "duration_ms": round(duration_ms, 2),
                "error": str(error),
            }

            # logger.exception logs the message and includes
            # the full Python traceback.
            logger.exception(
                json.dumps(error_log_entry)
            )

            # Re-raise the exception so FastAPI still knows
            # that the request failed.
            raise