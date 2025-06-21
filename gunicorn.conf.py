import os

# Bind to the port specified by the environment variable
BIND = f"0.0.0.0:{os.getenv('PORT', '5000')}"

# Worker configuration
WORKERS = 4
WORKER_CLASS = "sync"
WORKER_CONNECTIONS = 1000
TIMEOUT = 120
KEEPALIVE = 5

# Logging configuration
LOGLEVEL = "debug"
ACCESSLOG = "-"  # Log to stdout
ERRORLOG = "-"  # Log to stderr
CAPTURE_OUTPUT = True
ENABLE_STDIO_INHERITANCE = True

# Log format
ACCESS_LOG_FORMAT = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Preload application
PRELOAD_APP = True

# Process naming
PROC_NAME = "hackclub-dashboard"

# Security
FORWARDED_ALLOW_IPS = "*"
PROXY_ALLOW_IPS = "*"

# Maximum request size (10MB)
MAX_REQUESTS = 1000
MAX_REQUESTS_JITTER = 50


def when_ready(server):
    server.log.info("Server is ready. Spawning workers")


def worker_int(worker):
    worker.log.info("worker received INT or QUIT signal")


def pre_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)


def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)
