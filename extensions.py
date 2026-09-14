"""Singletons Flask extensions — évite les imports circulaires."""
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager

login_manager = LoginManager()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://",
)
