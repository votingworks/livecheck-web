import pytest
from unittest.mock import patch
from subprocess import CompletedProcess

from server.livecheck import VX_CUSTOM_CERT_FIELD, parseCertDetails, parseCertSubject

MOCK_DEV_MACHINE_ID = "DEV12345"
MOCK_VALID_SUBJECT =  f'subject=C = US, ST = CA, O = VotingWorks, {VX_CUSTOM_CERT_FIELD["MACHINE_ID"]} = {MOCK_DEV_MACHINE_ID}, '
MOCK_VALID_SUBJECT_CUSTOM_CERT_FIELDS = {
    VX_CUSTOM_CERT_FIELD["MACHINE_ID"]: MOCK_DEV_MACHINE_ID,
    "C": "US",
    "ST": "CA",
    "O": "VotingWorks"
}
MOCK_INVALID_SUBJECT =  f"invalid-subject=C = US, ST = CA, O = VotingWorks, "

@pytest.mark.parametrize("description, subject, openssl_stdout, openssl_stderr, expected_custom_cert_fields", [
    (
        "Successful OpenSSL subject extraction results in cert details",
        MOCK_VALID_SUBJECT,
        MOCK_VALID_SUBJECT,
        "",
        MOCK_VALID_SUBJECT_CUSTOM_CERT_FIELDS,
    ),
    (
        "Failed OpenSSL subject extraction results in empty cert details",
        MOCK_INVALID_SUBJECT,
        "",
        "Invalid cert",
        {},
    ),
])

def test_parse_cert_details(description, subject, openssl_stdout, openssl_stderr, expected_custom_cert_fields):
    with patch("server.livecheck.run") as mock_run:
        mock_run.return_value = CompletedProcess(
            args=["openssl", "x509", "-noout", "-subject", "-in", "cert"],
            returncode=0,
            stdout=openssl_stdout.encode("utf-8"),
            stderr=openssl_stderr.encode("utf-8")
        )

        result = parseCertDetails(subject)
        assert result == expected_custom_cert_fields
        
        
@pytest.mark.parametrize("description, subject, expected_custom_cert_fields", [
    (
        "Valid certificate is parsed",
        MOCK_VALID_SUBJECT,
        MOCK_VALID_SUBJECT_CUSTOM_CERT_FIELDS,
    ),
    (
        "Missing 'subject=' is invalid",
        f"C = US, ST = CA, O = VotingWorks, "
        f'{VX_CUSTOM_CERT_FIELD["MACHINE_ID"]} = {MOCK_DEV_MACHINE_ID}, ',
        {},
    ),
    (
        "Invalid cert-field is skipped over",
        f"subject=C = US, ST = CA, O = VotingWorks, invalid-cert-field,"
        f'{VX_CUSTOM_CERT_FIELD["MACHINE_ID"]} = {MOCK_DEV_MACHINE_ID}, ',
        {
            VX_CUSTOM_CERT_FIELD["MACHINE_ID"]: MOCK_DEV_MACHINE_ID,
            "C": "US",
            "ST": "CA",
            "O": "VotingWorks"
        },
    ),
])

def test_parse_cert_subject(description, subject, expected_custom_cert_fields):
    result = parseCertSubject(subject)
    assert result == expected_custom_cert_fields