"""Tests for secrethunter.detector. All test data below is synthetic/fake."""

from secrethunter.detector import Severity, scan_history, shannon_entropy


def test_detects_aws_access_key():
    lines = ["export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP"]
    findings = scan_history(lines)
    assert len(findings) == 1
    assert "AWS" in findings[0].reason
    assert findings[0].severity == Severity.HIGH


def test_detects_github_token():
    lines = ["git clone https://ghp_1234567890abcdef1234567890abcdef1234@github.com/x/y"]
    findings = scan_history(lines)
    assert any("GitHub" in f.reason for f in findings)


def test_detects_credential_in_url():
    lines = ["curl https://myuser:supersecretpassword@example.com/api"]
    findings = scan_history(lines)
    assert any("Credential in URL" in f.reason for f in findings)


def test_clean_line_produces_no_findings():
    lines = ["ls -la", "cd ~/projects", "git status", "echo hello"]
    findings = scan_history(lines)
    assert findings == []


def test_line_number_is_correctly_reported():
    lines = ["ls", "cd ..", "export API_KEY=AKIAABCDEFGHIJKLMNOP"]
    findings = scan_history(lines)
    assert findings[0].line_number == 3


def test_high_entropy_token_flagged():
    lines = ["export SECRET=aB3xQ9zM2pR7wK1vN8yT4uL6hJ0dF5gC"]
    findings = scan_history(lines)
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_low_entropy_string_not_flagged():
    lines = ["export MESSAGE=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    findings = scan_history(lines)
    assert findings == []


def test_entropy_check_scoped_to_secret_bearing_commands():
    lines = ["echo aB3xQ9zM2pR7wK1vN8yT4uL6hJ0dF5gC"]
    findings = scan_history(lines)
    assert findings == []


def test_shannon_entropy_of_repeated_char_is_zero():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_shannon_entropy_of_random_string_is_high():
    assert shannon_entropy("aB3xQ9zM2pR7wK1vN8yT") > 3.5
