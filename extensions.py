"""
Flask extensions initialization.
Extensions are created here and initialized later in the app factory.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize extensions without app context
db = SQLAlchemy()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour"],
    storage_uri="memory://"
)
