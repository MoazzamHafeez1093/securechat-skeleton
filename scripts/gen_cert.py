# This script generates certificates for server and client
# Each gets: private key + certificate signed by CA

import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

def generate_cert(entity_name, common_name):
    # Load CA certificate and key
    with open("certs/ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    with open("certs/ca_key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    # Generate private key for entity
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Create certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(ca_key, hashes.SHA256())
    )
    
    # Save private key
    with open(f"certs/{entity_name}_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    with open(f"certs/{entity_name}_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"✓ Generated {entity_name} certificate")

if __name__ == "__main__":
    generate_cert("server", "SecureChat Server")
    generate_cert("client", "SecureChat Client")