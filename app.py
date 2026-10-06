"""Point d'entrée — Sentinelle Nord Canada OSINT/TI platform."""
import os
from flask import Flask

from config import Config
from database import init_db
from extensions import limiter, login_manager
from models import User


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(
        __name__,
        template_folder="api/templates",
        static_folder="api/static",
    )
    app.config["SECRET_KEY"] = Config.SECRET_KEY
    app.config["SQLALCHEMY_DATABASE_URI"] = Config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    # Cookies sécurisés
    app.config["REMEMBER_COOKIE_DURATION"] = 60 * 60 * 24 * 7  # 7 jours
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # Overrides de test (appliqués avant les extensions)
    if test_config:
        app.config.update(test_config)

    # Init extensions
    init_db(app)
    login_manager.init_app(app)
    limiter.init_app(app)

    # Flask-Login
    login_manager.login_view = "auth.login_page"          # type: ignore[assignment]
    login_manager.login_message = "Connexion requise pour accéder à la plateforme."
    login_manager.login_message_category = "danger"

    # Blueprints
    from api.routes import bp as api_bp
    from auth.routes import auth_bp
    from compliance.routes import compliance_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(compliance_bp)

    # Scheduler Arctic (désactivable via SCHEDULER_ENABLED=false)
    if os.getenv("SCHEDULER_ENABLED", "true").lower() not in ("0", "false", "no"):
        from streaming.scheduler import start_scheduler
        start_scheduler(app)

    return app


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


app = create_app()

if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT,
            debug=(Config.ENV == "development"))
