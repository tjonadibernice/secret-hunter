"""Tests for secrethunter.models."""

import pytest
from pydantic import ValidationError

from secrethunter.models import ScanTarget


def test_valid_file_accepted(tmp_path):
    history_file = tmp_path / "fake_history"
    history_file.write_text("ls -la\ncd ~/projects\n")
    target = ScanTarget(path=history_file)
    assert target.path == history_file


def test_missing_file_raises(tmp_path):
    missing = tmp_path / "does_not_exist"
    with pytest.raises(ValidationError):
        ScanTarget(path=missing)


def test_empty_file_raises(tmp_path):
    empty_file = tmp_path / "empty_history"
    empty_file.write_text("")
    with pytest.raises(ValidationError):
        ScanTarget(path=empty_file)


def test_directory_raises(tmp_path):
    with pytest.raises(ValidationError):
        ScanTarget(path=tmp_path)
