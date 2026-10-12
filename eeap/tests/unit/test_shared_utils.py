import pytest

from eeap_shared.logging.setup import redact
from eeap_shared.utils.pagination import decode_cursor, encode_cursor, page


@pytest.mark.parametrize("text", [
    "Authorization: Bearer eyJhbGciOiJFZERTQSJ9.payload.sig",
    'password="hunter2-is-not-a-password"',
    "api_key=abcdef123456",
])
def test_redact_removes_secrets(text):
    redacted = redact(text)
    assert "hunter2" not in redacted
    assert "eyJhbGciOiJFZERTQSJ9" not in redacted
    assert "abcdef123456" not in redacted


def test_cursor_round_trip():
    value = {"asset_id": "DC01"}
    assert decode_cursor(encode_cursor(value)) == value
    assert decode_cursor(None) is None


def test_page_sets_next_cursor_only_when_more_rows_exist():
    rows = [{"id": i} for i in range(3)]
    full = page(rows, 2, lambda r: {"id": r["id"]})
    assert [r["id"] for r in full["items"]] == [0, 1]
    assert decode_cursor(full["next_cursor"]) == {"id": 1}
    last = page(rows[:2], 2, lambda r: {"id": r["id"]})
    assert last["next_cursor"] is None
