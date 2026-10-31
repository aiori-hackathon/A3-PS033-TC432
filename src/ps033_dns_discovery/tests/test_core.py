import json
import pytest
from discovery import validate_metadata

def valid_metadata():
    return {"name": "Health", "description": "Mock", "endpoint": "http://127.0.0.1:5055/health", "auth": "bearer", "token": "demo-token"}

def test_valid_metadata():
    assert validate_metadata(json.dumps(valid_metadata()))["name"] == "Health"

@pytest.mark.parametrize("raw", ['{"name":', '[]', 'null'])
def test_invalid_json_or_shape(raw):
    with pytest.raises(ValueError, match="Malformed metadata"):
        validate_metadata(raw)

def test_missing_field_rejected():
    data = valid_metadata(); del data["token"]
    with pytest.raises(ValueError, match="token"):
        validate_metadata(json.dumps(data))

@pytest.mark.parametrize("endpoint", ["http://example.com/health", "https://127.0.0.1:5055/health", "http://127.0.0.1:5055@evil.test/health", "http://127.0.0.1:9999/health", "http://127.0.0.1:5055/other"])
def test_unapproved_endpoint_rejected(endpoint):
    data = valid_metadata(); data["endpoint"] = endpoint
    with pytest.raises(ValueError, match="Rejected endpoint"):
        validate_metadata(json.dumps(data))

def test_unsupported_auth_rejected():
    data = valid_metadata(); data["auth"] = "basic"
    with pytest.raises(ValueError, match="Unsupported authentication"):
        validate_metadata(json.dumps(data))
