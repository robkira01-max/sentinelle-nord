"""Point d'entrée — Sentinelle Nord Canada OSINT/TI platform."""
import os
from flask import Flask
from config import Config
from database import init_db
from api.routes import bp as api_bp


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="api/templates",
        static_folder="api/static",
    )
    app.config["SECRET_KEY"] = Config.SECRET_KEY
    app.config["SQLALCHEMY_DATABASE_URI"] = Config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    init_db(app)
    app.register_blueprint(api_bp)

    # Scheduler Arctic (désactivable via SCHEDULER_ENABLED=false)
    if os.getenv("SCHEDULER_ENABLED", "true").lower() not in ("0", "false", "no"):
        from streaming.scheduler import start_scheduler
        start_scheduler(app)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT,
            debug=(Config.ENV == "development"))
