"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""
from pydantic import BaseModel, Field
from typing import Literal, Optional


# Control Plane Messages (Section 1.1)

class HelloMessage(BaseModel):
    """
    Client hello with certificate and nonce.
    
    Per assignment Section 1.1:
    { "type":"hello", "client_cert":"...PEM...", "nonce": base64 }
    """
    type: Literal["hello"] = "hello"
    client_cert: str = Field(..., description="PEM-encoded client certificate")
    nonce: str = Field(..., description="Base64-encoded random nonce")


class ServerHelloMessage(BaseModel):
    """
    Server hello with certificate and nonce.
    
    Per assignment Section 1.1:
    { "type":"server_hello", "server_cert":"...PEM...", "nonce": base64 }
    """
    type: Literal["server_hello"] = "server_hello"
    server_cert: str = Field(..., description="PEM-encoded server certificate")
    nonce: str = Field(..., description="Base64-encoded random nonce")


class RegisterMessage(BaseModel):
    """
    Registration message with hashed password.
    
    Per assignment Section 1.1 and 2.2:
    { "type":"register", "email":"", "username":"", 
      "pwd": base64(sha256(salt||pwd)), "salt": base64 }
    
    Note: pwd and salt are sent encrypted under temporary DH-derived key.
    """
    type: Literal["register"] = "register"
    email: str
    username: str
    pwd: str = Field(..., description="Base64(SHA256(salt||password))")
    salt: str = Field(..., description="Base64-encoded 16-byte salt")


class LoginMessage(BaseModel):
    """
    Login message with hashed password.
    
    Per assignment Section 1.1:
    { "type":"login", "email":"", "pwd": base64(sha256(salt||pwd)), "nonce": base64 }
    
    Note: pwd is sent encrypted under temporary DH-derived key.
    """
    type: Literal["login"] = "login"
    email: str
    pwd: str = Field(..., description="Base64(SHA256(salt||password))")
    nonce: str = Field(..., description="Base64-encoded random nonce")


# Key Agreement Messages (Section 1.2)

class DHClientMessage(BaseModel):
    """
    DH client message with parameters and public key.
    
    Per assignment Section 1.2:
    { "type":"dh_client", "g": int, "p": int, "A": int }
    
    Where A = g^a mod p (client's public key)
    """
    type: Literal["dh_client"] = "dh_client"
    g: int = Field(..., description="DH generator")
    p: int = Field(..., description="DH prime modulus")
    A: int = Field(..., description="Client's DH public key (g^a mod p)")


class DHServerMessage(BaseModel):
    """
    DH server message with public key.
    
    Per assignment Section 1.2:
    { "type":"dh_server", "B": int }
    
    Where B = g^b mod p (server's public key)
    """
    type: Literal["dh_server"] = "dh_server"
    B: int = Field(..., description="Server's DH public key (g^b mod p)")


# Data Plane Messages (Section 1.3)

class ChatMessage(BaseModel):
    """
    Encrypted and signed chat message.
    
    Per assignment Section 1.3:
    { "type":"msg", "seqno": n, "ts": unix_ms, "ct": base64, 
      "sig": base64(RSA_SIGN(SHA256(seqno||ts||ct))) }
    """
    type: Literal["msg"] = "msg"
    seqno: int = Field(..., description="Sequence number for replay protection")
    ts: int = Field(..., description="Unix timestamp in milliseconds")
    ct: str = Field(..., description="Base64-encoded ciphertext")
    sig: str = Field(..., description="Base64-encoded RSA signature")


# Non-Repudiation Message (Section 1.4)

class SessionReceipt(BaseModel):
    """
    Session receipt for non-repudiation.
    
    Per assignment Section 1.4:
    { "type":"receipt", "peer":"client|server", "first_seq":..., "last_seq":...,
      "transcript_sha256":hex, "sig":base64(RSA_SIGN(transcript_sha256)) }
    """
    type: Literal["receipt"] = "receipt"
    peer: str = Field(..., description="'client' or 'server'")
    first_seq: int = Field(..., description="First sequence number in transcript")
    last_seq: int = Field(..., description="Last sequence number in transcript")
    transcript_sha256: str = Field(..., description="Hex-encoded SHA-256 of transcript")
    sig: str = Field(..., description="Base64-encoded RSA signature over transcript hash")


# Response/Status Messages

class StatusMessage(BaseModel):
    """Generic status/response message."""
    type: str
    success: bool
    message: Optional[str] = None
    username: Optional[str] = None


class ErrorMessage(BaseModel):
    """Error message."""
    type: Literal["error"] = "error"
    message: str
