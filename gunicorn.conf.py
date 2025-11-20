
import os

# Bind to the port specified by the environment variable
bind = f"0.0.0.0:{os.getenv('PORT', '5000')}"

# Worker configuration
workers = 4
worker_class = "sync"
worker_connections = 1000
timeout = 120
keepalive = 5

# Logging configuration
loglevel = "info"
accesslog = "-"  # Log to stdout
errorlog = "-"   # Log to stderr
capture_output = True
enable_stdio_inheritance = True

# Log format
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Preload application
preload_app = True

# Process naming
proc_name = "hackclub-dashboard"

# Security
forwarded_allow_ips = "127.0.0.1"
proxy_allow_ips = "127.0.0.1"

# Maximum request size (10MB)
max_requests = 1000
max_requests_jitter = 50

def when_ready(server):
    server.log.info("Server is ready. Spawning workers")

def worker_int(worker):
    worker.log.info("worker received INT or QUIT signal")

def pre_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)
