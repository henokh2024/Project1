from prometheus_client import Counter, Histogram


# Counts every HTTP request handled by the API.
REQUEST_COUNT = Counter(
    "api_http_requests_total",
    "Total number of HTTP requests",
    ["method", "endpoint", "status_code"],
)


# Measures how long each HTTP request takes.
REQUEST_LATENCY = Histogram(
    "api_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "endpoint"],
)


# Counts incidents created through the API.
INCIDENTS_CREATED = Counter(
    "api_incidents_created_total",
    "Total number of incidents created",
)