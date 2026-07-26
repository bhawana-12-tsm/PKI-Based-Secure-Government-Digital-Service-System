import os
import hashlib
import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, BestAvailableEncryption, NoEncryption
)

CA_KEY_PATH  = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'certificates', 'ca_key.pem')
CA_CERT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'certificates', 'ca_cert.pem')

# ── Master key for keystore encryption (simulated HSM / secure key storage) ──
# In production this would come from an environment variable or secrets manager.
_MASTER_KEY = hashlib.sha256(
    os.environ.get('PKI_MASTER_KEY', 'nepal-gov-pki-master-2024-do-not-expose').encode()
).digest()  # 32-byte AES-256 key

_ca_key  = None
_ca_cert = None


# ─── CA setup ─────────────────────────────────────────────────────────────────

def _load_or_create_ca():
    global _ca_key, _ca_cert
    os.makedirs(os.path.dirname(CA_KEY_PATH), exist_ok=True)
    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        with open(CA_KEY_PATH, 'rb') as f:
            _ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(CA_CERT_PATH, 'rb') as f:
            _ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    else:
        _ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bagmati"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Kathmandu"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nepal Government PKI CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Nepal Gov Root CA"),
        ])
        now = datetime.now(timezone.utc)
        _ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(_ca_key, hashes.SHA256(), default_backend())
        )
        with open(CA_KEY_PATH, 'wb') as f:
            f.write(_ca_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
        with open(CA_CERT_PATH, 'wb') as f:
            f.write(_ca_cert.public_bytes(Encoding.PEM))


# ─── D. Secure Key Management — keystore encrypt/decrypt ──────────────────────

def _encrypt_private_key(private_key_pem: str) -> str:
    """Encrypt a PEM private key with AES-256-CBC using the master key.
    Returns base64-encoded  IV || ciphertext."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(_MASTER_KEY), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    data = private_key_pem.encode()
    # PKCS7 padding to block boundary
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    ct = enc.update(data) + enc.finalize()
    return base64.b64encode(iv + ct).decode()


def _decrypt_private_key(stored: str) -> str:
    """Decrypt a keystore-encrypted private key. Returns PEM string."""
    raw = base64.b64decode(stored)
    iv, ct = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(_MASTER_KEY), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    data = dec.update(ct) + dec.finalize()
    # Remove PKCS7 padding
    pad_len = data[-1]
    return data[:-pad_len].decode()


def _load_private_key(stored_pem_or_encrypted: str):
    """Auto-detect keystore blob vs plain PEM and return a private key object."""
    value = stored_pem_or_encrypted.strip()
    if value.startswith('-----'):
        # Plain PEM (legacy rows or officer/admin seeded before keystore was added)
        pem = value
    else:
        pem = _decrypt_private_key(value)
    return serialization.load_pem_private_key(
        pem.encode(), password=None, backend=default_backend()
    )


# ─── Key + certificate generation ─────────────────────────────────────────────

def generate_user_keys_and_cert(full_name, email, username):
    _load_or_create_ca()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key  = private_key.public_key()

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bagmati"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Kathmandu"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nepal Government Digital Services"),
        x509.NameAttribute(NameOID.COMMON_NAME, full_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(_ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(_ca_key, hashes.SHA256(), default_backend())
    )

    plain_pem       = private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode()
    encrypted_store = _encrypt_private_key(plain_pem)          # D. keystore
    public_key_pem  = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    cert_pem        = cert.public_bytes(Encoding.PEM).decode()
    serial          = str(cert.serial_number)
    expires_at      = cert.not_valid_after_utc.isoformat()

    return encrypted_store, public_key_pem, cert_pem, serial, expires_at


# ─── Hashing ──────────────────────────────────────────────────────────────────

def hash_file(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


# ─── Signing ──────────────────────────────────────────────────────────────────

def sign_data(private_key_stored: str, data_bytes: bytes) -> str:
    """Sign data_bytes with the stored (possibly keystore-encrypted) private key."""
    private_key = _load_private_key(private_key_stored)
    signature   = private_key.sign(data_bytes, asym_padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode()


def sign_application(private_key_stored: str, form_data_dict: dict, document_hashes: dict):
    payload = json.dumps({
        'form_data':       form_data_dict,
        'document_hashes': document_hashes,
        'timestamp':       datetime.utcnow().isoformat()
    }, sort_keys=True).encode()
    data_hash = hashlib.sha256(payload).hexdigest()
    signature = sign_data(private_key_stored, payload)
    return signature, data_hash, payload


# ─── B. Hybrid Encryption ─────────────────────────────────────────────────────

def hybrid_encrypt(plaintext: bytes, public_key_pem: str) -> tuple[bytes, str]:
    """
    Encrypt *plaintext* with AES-256-CBC (random key + IV).
    Encrypt the AES key with the user's RSA public key (OAEP/SHA-256).
    Returns (ciphertext_with_iv, base64_encrypted_aes_key).
    """
    aes_key = os.urandom(32)   # AES-256
    iv      = os.urandom(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    enc    = cipher.encryptor()
    pad_len = 16 - (len(plaintext) % 16)
    padded  = plaintext + bytes([pad_len]) * pad_len
    ct      = enc.update(padded) + enc.finalize()

    public_key     = serialization.load_pem_public_key(
        public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
        backend=default_backend()
    )
    enc_aes_key    = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None)
    )
    return iv + ct, base64.b64encode(enc_aes_key).decode()


def hybrid_decrypt(ciphertext_with_iv: bytes, encrypted_aes_key_b64: str,
                   private_key_stored: str) -> bytes:
    """
    Decrypt using the stored private key to recover the AES key,
    then decrypt the document with AES-256-CBC.
    """
    private_key = _load_private_key(private_key_stored)
    enc_aes_key = base64.b64decode(encrypted_aes_key_b64)
    aes_key     = private_key.decrypt(
        enc_aes_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None)
    )
    iv, ct = ciphertext_with_iv[:16], ciphertext_with_iv[16:]
    cipher  = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    dec     = cipher.decryptor()
    data    = dec.update(ct) + dec.finalize()
    pad_len = data[-1]
    return data[:-pad_len]


# ─── E. Enhanced Signature Verification ───────────────────────────────────────

class VerificationResult:
    """Structured result from full_verify_document."""
    __slots__ = ('ok', 'result_code', 'message', 'details')

    def __init__(self, ok, result_code, message, details=None):
        self.ok          = ok
        self.result_code = result_code   # 'valid'|'invalid'|'tampered'|'revoked'|'error'
        self.message     = message
        self.details     = details or {}


def full_verify_document(file_bytes: bytes, stored_hash: str, signature_b64: str,
                          public_key_pem: str, cert_is_valid: int) -> VerificationResult:
    """
    E. Security Validation — runs all checks in order:
      1. Certificate validity / revocation
      2. SHA-256 document hash (integrity)
      3. RSA digital signature
    """
    # 1. Certificate revocation
    if not cert_is_valid:
        return VerificationResult(False, 'revoked', 'CERTIFICATE REVOKED',
                                  {'check': 'certificate_status'})

    # 2. Hash integrity
    current_hash = hashlib.sha256(file_bytes).hexdigest()
    if current_hash != stored_hash:
        return VerificationResult(False, 'tampered', 'DOCUMENT HAS BEEN TAMPERED',
                                  {'stored_hash': stored_hash, 'current_hash': current_hash})

    # 3. RSA signature
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
            backend=default_backend()
        )
        sig = base64.b64decode(signature_b64)
        public_key.verify(sig, file_bytes, asym_padding.PKCS1v15(), hashes.SHA256())
        return VerificationResult(True, 'valid', 'VALID SIGNATURE',
                                  {'hash': current_hash})
    except Exception as exc:
        return VerificationResult(False, 'invalid', 'INVALID SIGNATURE',
                                  {'error': str(exc)})


# ─── C. Replay Attack Protection ──────────────────────────────────────────────

def generate_nonce() -> str:
    """Cryptographically secure 32-byte hex nonce."""
    return secrets.token_hex(32)


# kept for backward compat in tests
def verify_signature(public_key_pem: str, data_bytes: bytes, signature_b64: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem,
            backend=default_backend()
        )
        sig = base64.b64decode(signature_b64)
        public_key.verify(sig, data_bytes, asym_padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def verify_application_signature(public_key_pem, payload_bytes, signature_b64):
    return verify_signature(public_key_pem, payload_bytes, signature_b64)
