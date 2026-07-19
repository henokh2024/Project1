from app.middleware import LoggingMiddleware

from app.routes.auth_routes import router as auth_router
from app.routes.incident_routes import router as incident_router

import logging

# Prevent verbose Azure SDK/exporter messages from flooding Application Insights.
logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(
    logging.WARNING
)
logging.getLogger(
    "azure.monitor.opentelemetry.exporter.export._base"
).setLevel(logging.WARNING)


from azure.monitor.opentelemetry import configure_azure_monitor

configure_azure_monitor()

# Create the FastAPI application object.
# This is the central object that holds all routes,
# middleware, settings, and application configuration.
from fastapi import FastAPI
app = FastAPI(
    title="Secure Microservice API",
    description="Secure FastAPI microservice with authentication and observability.",
    version="1.0.0",
  
)

app.add_middleware(LoggingMiddleware)
app.include_router(auth_router)
app.include_router(incident_router)


# Root endpoint
# This route executes whenever someone visits:
# http://localhost:8000/
@app.get("/")
def root():
    return {
        "message": "Secure Microservice API is running"
    }


# Health check endpoint
# Monitoring systems use this endpoint to verify
# that the application is alive and responding.
@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }