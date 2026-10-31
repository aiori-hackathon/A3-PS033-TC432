"""In-process DNSSEC tests; no network ports are required."""
import pytest
import dns.message
from dns_lab import DNSLab
from discovery import verify_txt

@pytest.fixture
def lab():
    try:
        return DNSLab()
    except RuntimeError:
        pytest.skip("Run python setup_lab.py to create local DNSSEC keys")

def response_for(lab):
    query = dns.message.make_query("health.diag.test.", "TXT")
    return lab.answer(query)

def test_valid_txt_signature_verifies(lab):
    response = response_for(lab)
    rrset = verify_txt("health.diag.test.", response)
    assert rrset.name.to_text() == "health.diag.test."

def test_bogus_txt_signature_is_rejected(lab):
    lab.set_mode("bogus")
    with pytest.raises(Exception):
        verify_txt("health.diag.test.", response_for(lab))
