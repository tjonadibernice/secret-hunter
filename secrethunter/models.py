"""Pydantic model for validating the CLI's input file."""

from pathlib import Path
from pydantic import BaseModel, field_validator


class ScanTarget(BaseModel):
    """A validated, readable file to scan for secrets."""

    path: Path

    @field_validator("path")
    @classmethod
    def path_must_exist_and_be_readable(cls, value: Path) -> Path:
        if not value.exists():
            raise ValueError(f"File not found: {value}")
        if not value.is_file():
            raise ValueError(f"Not a file: {value}")
        if not value.stat().st_size:
            raise ValueError(f"File is empty: {value}")
        return value
