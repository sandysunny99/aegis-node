"""
Aegis Node — Dataset lookup by public identifier.

Integer primary keys stay internal. Every API path and response uses the
unguessable `public_id` (uuid4 hex) so dataset IDs cannot be enumerated (S1).
"""

import re

from fastapi import HTTPException
from models import DatasetRecord
from sqlalchemy import select
from sqlalchemy.orm import Session

_PUBLIC_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def get_dataset_by_public_id(db: Session, public_id: str) -> DatasetRecord:
    """Return the dataset for `public_id`, or raise the same 404 for malformed and unknown ids."""
    if not _PUBLIC_ID_RE.fullmatch(public_id or ""):
        raise HTTPException(status_code=404, detail="Resource not found.")
    record = db.scalar(select(DatasetRecord).where(DatasetRecord.public_id == public_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Resource not found.")
    return record
