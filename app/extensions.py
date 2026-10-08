"""Extensions Flask partagees (instanciees ici, branchees dans create_app)."""

from flask_migrate import Migrate

from app.models import db

migrate = Migrate()

__all__ = ["db", "migrate"]
