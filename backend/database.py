"""
Aegis Node — SQLite database engine and session factory.
Uses SQLAlchemy 2.x with synchronous driver (sqlite3 stdlib — no extra driver needed).
"""

from config import settings
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# Database engine uses database_url configured in settings
DATABASE_URL = settings.database_url
is_sqlite = DATABASE_URL.startswith("sqlite")
connect_args = {"check_same_thread": False} if is_sqlite else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,
)

if is_sqlite:
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Declarative base that all SQLAlchemy models inherit from."""
    pass


def get_db():
    """FastAPI dependency — yields a database session, rolls back on exception, always closes."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def create_all_tables() -> None:
    """Creates all tables if they do not exist. Called once at app startup."""
    Base.metadata.create_all(bind=engine)
