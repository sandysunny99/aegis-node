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
    _migrate_dataset_public_id()
    _migrate_remediation_integrity_method()


def _migrate_dataset_public_id() -> None:
    """
    Alembic-free migration for databases created before `datasets.public_id` existed:
    add the column, backfill a uuid4 hex per row, then add the unique index.
    Idempotent; a no-op on fresh databases created by create_all().
    """
    import uuid

    from sqlalchemy import inspect, text

    columns = {c["name"] for c in inspect(engine).get_columns("datasets")}
    with engine.begin() as conn:
        if "public_id" not in columns:
            conn.execute(text("ALTER TABLE datasets ADD COLUMN public_id VARCHAR(32)"))
        missing = conn.execute(text("SELECT id FROM datasets WHERE public_id IS NULL")).all()
        for (row_id,) in missing:
            conn.execute(
                text("UPDATE datasets SET public_id = :pid WHERE id = :id"),
                {"pid": uuid.uuid4().hex, "id": row_id},
            )
        conn.execute(
            text("CREATE UNIQUE INDEX IF NOT EXISTS ix_datasets_public_id ON datasets (public_id)")
        )


def _migrate_remediation_integrity_method() -> None:
    """Add remediations.integrity_method (C11) to databases created before it existed."""
    from sqlalchemy import inspect, text

    columns = {c["name"] for c in inspect(engine).get_columns("remediations")}
    if "integrity_method" not in columns:
        with engine.begin() as conn:
            conn.execute(text(
                "ALTER TABLE remediations ADD COLUMN integrity_method VARCHAR(16) "
                "NOT NULL DEFAULT 'estimated_rows'"
            ))
