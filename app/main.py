from fastapi import FastAPI


# Create the FastAPI application object.
# This is the central object that holds all routes,
# middleware, settings, and application configuration.
app = FastAPI(
    title="Secure Microservice API",
    description="Secure FastAPI microservice with authentication and observability.",
    version="1.0.0",
)


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