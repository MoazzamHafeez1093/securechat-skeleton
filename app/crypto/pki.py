"""X.509 validation: signed-by-CA, validity window, CN/SAN."""
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import datetime
from typing import Tuple, Optional


def load_certificate(cert_path: str) -> x509.Certificate:
    """
    Load X.509 certificate from PEM file.
    
    Args:
        cert_path: path to PEM-encoded certificate file
        
    Returns:
        Certificate object
    """
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def load_private_key(key_path: str, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    """
    Load RSA private key from PEM file.
    
    Args:
        key_path: path to PEM-encoded private key file
        password: optional password for encrypted keys
        
    Returns:
        RSAPrivateKey object
    """
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), 
            password=password, 
            backend=default_backend()
        )


def cert_from_pem_string(cert_pem_string: str) -> x509.Certificate:
    """
    Parse X.509 certificate from PEM string.
    
    Args:
        cert_pem_string: PEM-encoded certificate as string
        
    Returns:
        Certificate object
    """
    return x509.load_pem_x509_certificate(
        cert_pem_string.encode('utf-8'), 
        default_backend()
    )


def cert_to_pem_string(cert: x509.Certificate) -> str:
    """
    Convert certificate object to PEM string.
    
    Args:
        cert: Certificate object
        
    Returns:
        PEM-encoded certificate as string
    """
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')


def get_cert_public_key(cert: x509.Certificate) -> rsa.RSAPublicKey:
    """
    Extract RSA public key from certificate.
    
    Args:
        cert: Certificate object
        
    Returns:
        RSAPublicKey object
    """
    return cert.public_key()


def get_cert_common_name(cert: x509.Certificate) -> str:
    """
    Extract Common Name (CN) from certificate subject.
    
    Args:
        cert: Certificate object
        
    Returns:
        Common Name string
    """
    cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if not cn_attrs:
        raise ValueError("Certificate has no Common Name")
    return cn_attrs[0].value


def validate_certificate(
    cert: x509.Certificate, 
    ca_cert: x509.Certificate, 
    expected_cn: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Validate X.509 certificate according to assignment requirements.
    
    Checks performed:
    1. Signature chain validity (signed by trusted CA)
    2. Expiry date and validity period
    3. Common Name (CN) match (optional)
    
    Args:
        cert: Certificate to validate
        ca_cert: CA certificate (trusted root)
        expected_cn: Expected Common Name (optional)
        
    Returns:
        Tuple (is_valid: bool, error_message: str)
        - (True, "Certificate valid") if all checks pass
        - (False, "BAD_CERT: ...") if any check fails
    """
    try:
        # Check 1: Verify signature chain (signed by CA)
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
        except InvalidSignature:
            return False, "BAD_CERT: Invalid CA signature"
        except Exception as e:
            return False, f"BAD_CERT: Signature verification failed - {str(e)}"
        
        # Check 2: Verify validity period (not expired, not before valid date)
        now = datetime.datetime.now(datetime.timezone.utc)
        
        # Convert to timezone-aware if needed
        not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
        
        # Make naive datetimes timezone-aware for comparison
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=datetime.timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=datetime.timezone.utc)
        
        if now < not_before:
            return False, "BAD_CERT: Certificate not yet valid"
        if now > not_after:
            return False, "BAD_CERT: Certificate expired"
        
        # Check 3: Verify Common Name (if expected_cn provided)
        if expected_cn:
            try:
                actual_cn = get_cert_common_name(cert)
                if actual_cn != expected_cn:
                    return False, f"BAD_CERT: Common Name mismatch (expected: {expected_cn}, got: {actual_cn})"
            except ValueError as e:
                return False, f"BAD_CERT: {str(e)}"
        
        return True, "Certificate valid"
        
    except Exception as e:
        return False, f"BAD_CERT: Validation error - {str(e)}"


def validate_certificate_from_pem(
    cert_pem_string: str, 
    ca_cert_path: str, 
    expected_cn: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Validate certificate from PEM string against CA certificate file.
    
    Args:
        cert_pem_string: PEM-encoded certificate as string
        ca_cert_path: path to CA certificate PEM file
        expected_cn: Expected Common Name (optional)
        
    Returns:
        Tuple (is_valid: bool, error_message: str)
    """
    try:
        cert = cert_from_pem_string(cert_pem_string)
        ca_cert = load_certificate(ca_cert_path)
        return validate_certificate(cert, ca_cert, expected_cn)
    except Exception as e:
        return False, f"BAD_CERT: Failed to load certificates - {str(e)}"
