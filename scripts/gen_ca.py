# This script generates:
# 1. CA private key (ca_key.pem)
# 2. CA self-signed certificate (ca_cert.pem)

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

# Generate RSA private key for CA
ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Create CA certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
    x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA")
])

ca_cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(ca_private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(ca_private_key, hashes.SHA256())
)

# Save CA private key
with open("certs/ca_key.pem", "wb") as f:
    f.write(ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save CA certificate
with open("certs/ca_cert.pem", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

print("✓ CA created: certs/ca_key.pem and certs/ca_cert.pem")