
from subprocess import call, run
import tempfile

root_cert_text = """
-----BEGIN CERTIFICATE-----
MIIB+TCCAZ+gAwIBAgIUBfRZ4pVvvyZjA/Cmt2BMzygiKi4wCgYIKoZIzj0EAwIw
UTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtWb3RpbmdXb3Jr
czEfMB0GA1UEAwwWVm90aW5nV29ya3MgUHJvZHVjdGlvbjAgFw0yNDEyMTMxNzEy
NTZaGA8yMTI0MTExOTE3MTI1NlowUTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNB
MRQwEgYDVQQKDAtWb3RpbmdXb3JrczEfMB0GA1UEAwwWVm90aW5nV29ya3MgUHJv
ZHVjdGlvbjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNEZfmGzeJ/ArfO0f1wo
djnohC3ZSgxBHjb/pZtoBBBX31oiFgFIeZAbshT+4UuhzyptWvaWPH2B7do8xzzw
7pijUzBRMB0GA1UdDgQWBBR5+Pdiub7a7ZEZyzt9Muyo4hGb9DAfBgNVHSMEGDAW
gBR5+Pdiub7a7ZEZyzt9Muyo4hGb9DAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
BAMCA0gAMEUCIQDYlTy11MmDioUW85o+Ww1TgVLptyYMtvZoci1JGEqvPQIgFK25
ocbJjTzQ1+mo8d4pOoEWgVxyS4ZFpitvJseeULg=
-----END CERTIFICATE-----
"""

root_cert_text_dev = """
-----BEGIN CERTIFICATE-----
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

VX_IANA_ENTERPRISE_OID = '1.3.6.1.4.1.59817'

VX_CUSTOM_CERT_FIELD = {
    "MACHINE_ID": f"{VX_IANA_ENTERPRISE_OID}.6",
}

def makeTempFile(content, mode="w", encoding="utf-8"):
    tf = tempfile.NamedTemporaryFile(mode=mode, encoding=encoding, delete=False)
    tf.write(content)
    return tf.name

def parseCertDetails(cert):
    response = run(['openssl', 'x509', '-noout', '-subject', '-in', cert], capture_output = True).stdout
    cert_subject_string = response.decode('utf-8').strip()
    return parseCertSubject(cert_subject_string)

def parseCertSubject(cert_subject_string):
    if not cert_subject_string.startswith("subject="):
        return {}
    cert_subject = cert_subject_string.replace("subject=", "").strip()
    cert_fields_list = [field.strip() for field in cert_subject.split(",")]
    cert_fields = {}
    for cert_field in cert_fields_list:
        if "=" in cert_field:
            field_name, field_value = cert_field.split("=", 1)
            cert_fields[field_name.strip()] = field_value.strip()
    return cert_fields

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
    is_dev = False
    if cert_verification_result != 0:
        # attempt to verify with dev certificate as a fallback
        call(['rm', root_cert_file])
        root_cert_file = makeTempFile(root_cert_text_dev)
        cert_verification_result_dev = call(['openssl', 'verify', '-CAfile', root_cert_file, cert_file])
        if cert_verification_result_dev != 0:
            call(['rm', f"{root_cert_file} {cert_file}"])
            return None
        is_dev = True

    # extract public key from certificate
    public_key_text = run(['openssl', 'x509', '-noout', '-pubkey', '-in', cert_file], capture_output = True).stdout
    public_key_file = makeTempFile(public_key_text,"wb", None)

    # verify signature
    message_file = makeTempFile(message)
    signature_file = makeTempFile(signature)
    signature_raw = run(['base64', '-d', signature_file], capture_output = True).stdout
    signature_raw_file = makeTempFile(signature_raw, "wb", None)
    verify_result = run(['openssl', 'dgst', '-sha256', '-verify', public_key_file, '-signature', signature_raw_file, message_file], capture_output=True)

    if verify_result.returncode == 0 and verify_result.stdout == b"Verified OK\n":
        if vxsuite_version == "v3":
            machine_id, timestamp, election_id = fields
            return_val = {
                "machine_id": machine_id,
                "election_id": election_id,
                "timestamp": timestamp
            }
        else:
            assert vxsuite_version == "v4"
            cert_details = parseCertDetails(cert_file)
            if VX_CUSTOM_CERT_FIELD["MACHINE_ID"] in cert_details:
                machine_id = cert_details[VX_CUSTOM_CERT_FIELD["MACHINE_ID"]]
                system_hash, software_version, election_id, timestamp = fields
                if is_dev:
                    software_version = "For internal testing only – " + software_version
                return_val = {
                    "system_hash": system_hash,
                    "software_version": software_version,
                    "machine_id": machine_id,
                    "election_id": election_id,
                    "timestamp": timestamp
                }
            else:
                return_val = None
    else:
        print(verify_result)
        return_val = None
    
    # delete tmp files
    for f in [root_cert_file, cert_file, public_key_file, message_file, signature_file, signature_raw_file]:
        call(['rm', f])
        
    return return_val
