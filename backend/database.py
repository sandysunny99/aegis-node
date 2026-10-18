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
    _migrate_remediation_rescan_report()
    _migrate_scan_history_columns()


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


def _migrate_remediation_rescan_report() -> None:
    """Add scan_reports.scan_target and remediations.rescan_report_id to older databases."""
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    scan_columns = {c["name"] for c in inspector.get_columns("scan_reports")}
    remediation_columns = {c["name"] for c in inspector.get_columns("remediations")}
    with engine.begin() as conn:
        if "scan_target" not in scan_columns:
            conn.execute(text(
                "ALTER TABLE scan_reports ADD COLUMN scan_target VARCHAR(16) "
                "NOT NULL DEFAULT 'original'"
            ))
        if "rescan_report_id" not in remediation_columns:
            conn.execute(text(
                "ALTER TABLE remediations ADD COLUMN rescan_report_id INTEGER "
                "REFERENCES scan_reports(id)"
            ))


def _migrate_scan_history_columns() -> None:
    """
    Add scan_reports.public_id / started_at / profile / av_provider to older databases
    and backfill a public_id per existing row. scan_events is a new table (create_all).
    Existing rows are never rewritten otherwise.
    """
    import uuid

    from sqlalchemy import inspect, text

    columns = {c["name"] for c in inspect(engine).get_columns("scan_reports")}
    with engine.begin() as conn:
        if "public_id" not in columns:
            conn.execute(text("ALTER TABLE scan_reports ADD COLUMN public_id VARCHAR(32)"))
        for name, ddl in (("started_at", "TIMESTAMP"), ("profile", "VARCHAR(16)"), ("av_provider", "VARCHAR(32)")):
            if name not in columns:
                conn.execute(text(f"ALTER TABLE scan_reports ADD COLUMN {name} {ddl}"))
        missing = conn.execute(text("SELECT id FROM scan_reports WHERE public_id IS NULL")).all()
        for (row_id,) in missing:
            conn.execute(
                text("UPDATE scan_reports SET public_id = :pid WHERE id = :id"),
                {"pid": uuid.uuid4().hex, "id": row_id},
            )
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS ix_scan_reports_public_id ON scan_reports (public_id)"
        ))
