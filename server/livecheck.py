
from subprocess import call, run
import tempfile

root_cert_text = """
-----BEGIN CERTIFICATE-----
MIIBtzCCAV2gAwIBAgIUJXljpuonoCbjPFgRgYS42EUlRnAwCgYIKoZIzj0EAwIw
MDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtWb3RpbmdXb3Jr
czAgFw0yMzA3MDUyMDUxMDdaGA8yMTIzMDYxMTIwNTEwN1owMDELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQKDAtWb3RpbmdXb3JrczBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABDpuTIaivOkpG7zscOpujtz2LLYewTAInfLW1nOAEXh7
PVP43j0YNq25ZUyb2lTm57w84R584M9QxW27cIHbDbmjUzBRMB0GA1UdDgQWBBQT
89+KLrq+jierz3qBWK57sf3QGTAfBgNVHSMEGDAWgBQT89+KLrq+jierz3qBWK57
sf3QGTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIF07Es6YehPa
qF9kKw+eTlNvt/9I+Zbqut4XBWD4q7NTAiEA/XhKGlC1zu6UK9oYqbw77RXMqQtf
UNH5nCCoUC/6/nM=
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

def parseCertDetails(public_key_text):
    public_key_string = public_key_text.strip()
    if not public_key_string.startswith("subject="):
        return {}

    cert_subject = public_key_string.replace("subject=", "").strip()
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
        if len(fields) == 5:
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
        cert_details = parseCertDetails(certificate_without_envelope)
        machine_id = cert_details[VX_CUSTOM_CERT_FIELD["MACHINE_ID"]]
        system_hash, software_version, election_id, timestamp = fields
        return {
            "system_hash": system_hash,
            "software_version": software_version,
            "machine_id": machine_id,
            "election_id": election_id,
            "timestamp": timestamp
        }
    else:
        print(verify_result)
        return None
