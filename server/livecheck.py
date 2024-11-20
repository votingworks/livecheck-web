
from subprocess import call, run
import tempfile

# root_cert_text = """
# -----BEGIN CERTIFICATE-----
# MIIBtzCCAV2gAwIBAgIUJXljpuonoCbjPFgRgYS42EUlRnAwCgYIKoZIzj0EAwIw
# MDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtWb3RpbmdXb3Jr
# czAgFw0yMzA3MDUyMDUxMDdaGA8yMTIzMDYxMTIwNTEwN1owMDELMAkGA1UEBhMC
# VVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtWb3RpbmdXb3JrczBZMBMGByqGSM49
# AgEGCCqGSM49AwEHA0IABDpuTIaivOkpG7zscOpujtz2LLYewTAInfLW1nOAEXh7
# PVP43j0YNq25ZUyb2lTm57w84R584M9QxW27cIHbDbmjUzBRMB0GA1UdDgQWBBQT
# 89+KLrq+jierz3qBWK57sf3QGTAfBgNVHSMEGDAWgBQT89+KLrq+jierz3qBWK57
# sf3QGTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIF07Es6YehPa
# qF9kKw+eTlNvt/9I+Zbqut4XBWD4q7NTAiEA/XhKGlC1zu6UK9oYqbw77RXMqQtf
# UNH5nCCoUC/6/nM=
# -----END CERTIFICATE-----
# """

root_cert_text = """-----BEGIN CERTIFICATE-----
MIIBtjCCAV2gAwIBAgIUD5z+lzBU64i8+7ZarbmofAk9yjAwCgYIKoZIzj0EAwIw
MDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtWb3RpbmdXb3Jr
czAgFw0yNDEwMjgwNDExMzVaGA8yMTI0MTAwNDA0MTEzNVowMDELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtWb3RpbmdXb3JrczBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABJDLSJQlKgCPZSgP+ZVpgareR1KWWRd4FjR94JymY21Q
AcxLmgCD9jWnq+lp6SVy1Dz/NJ6Au23oRNgvWqGi8emjUzBRMB0GA1UdDgQWBBRM
c0o7/6216xmY8apne2R8nQnmrTAfBgNVHSMEGDAWgBRMc0o7/6216xmY8apne2R8
nQnmrTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIG1WBl7HOeDB
ftdu7Xmh0G4kzGktQ5hkJeOzRXNn346bAiB6QIjc1c61pM+E/MME4TXdOgmaS1gt
QgBhqrQsjg5eTQ==
-----END CERTIFICATE-----
"""

def makeTempFile(content, mode="w", encoding="utf-8"):
    tf = tempfile.NamedTemporaryFile(mode=mode, encoding=encoding, delete=False)
    tf.write(content)
    return tf.name

def processCodeData(data):
    components = data.split(";")

    if len(components) != 3:
        return None

    message, signature, certificate_without_envelope = components

    message_parts = message.split("//")
    if len(message_parts) != 3:
        return None

    version, header, fields_str = message_parts

    if version != "1":
        return None

    vxsuite_version = None

    # Live Check (legacy feature name)
    if header == "lc":
        fields = fields_str.split("/")
        if len(fields) == 3:
            vxsuite_version = "v3"
    # Signed hash validation, version 1
    elif header =="shv1":
        fields = fields_str.split("#")
        if len(fields) == 4:
            vxsuite_version = "v4"

    if not vxsuite_version:
        return None
    
    certificate = "-----BEGIN CERTIFICATE-----\n" + certificate_without_envelope.strip() + "\n-----END CERTIFICATE-----"

    # verify certificate
    root_cert_file = makeTempFile(root_cert_text)
    cert_file = makeTempFile(certificate)

    cert_verification_result = call(['openssl', 'verify', '-CAfile', root_cert_file, cert_file])
    if cert_verification_result != 0:
        return None

    # extract public key from certificate
    public_key_text = run(['openssl', 'x509', '-noout', '-pubkey', '-in', cert_file], capture_output = True).stdout
    public_key_file = makeTempFile(public_key_text,"wb", None)

    # verify signature
    message_file = makeTempFile(message)
    signature_file = makeTempFile(signature)
    signature_raw = run(['base64', '-d', signature_file], capture_output = True).stdout
    signature_raw_file = makeTempFile(signature_raw, "wb", None)

    verify_result = run(['openssl', 'dgst', '-sha256', '-verify', public_key_file, '-signature', signature_raw_file, message_file], capture_output=True)

    # delete tmp files
    for f in [root_cert_file, cert_file, public_key_file, message_file, signature_file, signature_raw_file]:
        call(['rm', f])

    if verify_result.returncode == 0 and verify_result.stdout == b"Verified OK\n":
        if vxsuite_version == "v3":
            machine_id, timestamp, election_id = fields
            return {
                "machine_id": machine_id,
                "election_id": election_id,
                "timestamp": timestamp
            }

        assert vxsuite_version == "v4"
        system_hash, software_version, election_id, timestamp = fields
        return {
            "system_hash": system_hash,
            "software_version": software_version,
            # "machine_id": machine_id,
            "election_id": election_id,
            "timestamp": timestamp
        }
    else:
        print(verify_result)
        return None

if __name__ == "__main__":
    data = """1//shv1//UNVERIFIED==================================#dev#292e786-7bdeb2d#2024-11-20T21:32:53.306Z;MEQCIBSB+qEfA4Cb4QuA9y5y8t4Tyb3/+GsdaUDVU0lvwTKEAiB3E7RRjkvgLEpFywFmRdJ/beiNpYDPmPrpeZ13og/9Cg==;
MIIB+jCCAaCgAwIBAgIUQb1QWvhK6xmC7VeRR7ZDSDYOhdswCgYIKoZIzj0EAwIw
MDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtWb3RpbmdXb3Jr
czAgFw0yNDEwMjgwNDExMzVaGA8yMTI0MTAwNDA0MTEzNVowczELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtWb3RpbmdXb3JrczEUMBIGCSsGAQQB
g9MpAQwFYWRtaW4xEzARBgkrBgEEAYPTKQYMBDAwMDAxFjAUBgkrBgEEAYPTKQIM
B3Z4LnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASK1P8exeoK38cPkPX9
9p5SC/Kc+n5Pb+O6dYcGynn9M6aNMVd7+3af3FhkTHylkYNTgvrXzVPlf2h1uHBD
m1nio1MwUTAdBgNVHQ4EFgQUorK8KERcQS4HAEC04vzPakZ3SCUwHwYDVR0jBBgw
FoAUTHNKO/+ttesZmPGqZ3tkfJ0J5q0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO
PQQDAgNIADBFAiAN1t3y3g58ikteaFHuphjLpwzB3WNdWvT7k/xftlzbSgIhAL3n
eBs4/XVP5afRUZWzJAP836mpqCeAEBXKv/0IVagd
"""
    print(processCodeData(data))
