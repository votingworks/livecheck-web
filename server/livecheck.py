
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

    version, header, fields = message_parts

    if version != "1" or header != "lc":
        return None

    machine_id, timestamp, election_id = fields.split("/")
    
    certificate = "-----BEGIN CERTIFICATE-----\n" + certificate_without_envelope.strip() + "\n-----END CERTIFICATE-----"
    print(certificate)

    # verify certificate
    root_cert_file = makeTempFile(root_cert_text)
    cert_file = makeTempFile(certificate)

    cert_verification_result = call(['openssl', 'verify', '-CAfile', root_cert_file, cert_file])
    if cert_verification_result != 0:
        return None

    print("got cert verification result")
    
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
        return {
            "machine_id": machine_id,
            "timestamp": timestamp,
            "election_id": election_id
        }
    else:
        print(verify_result)
        return None


