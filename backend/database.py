"""
Aegis Node — SQLite database engine and session factory.
Uses SQLAlchemy 2.x with synchronous driver (sqlite3 stdlib — no extra driver needed).
"""

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# ─── Database file sits at the project root (gitignored) ─────────────────────
_DB_PATH = Path(__file__).parent / "aegis_node.db"
DATABASE_URL = f"sqlite:///{_DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # required for SQLite + FastAPI
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base that all SQLAlchemy models inherit from."""
    pass


def get_db():
    """FastAPI dependency — yields a database session, always closes after request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_all_tables() -> None:
    """Creates all tables if they do not exist. Called once at app startup."""
    Base.metadata.create_all(bind=engine)
