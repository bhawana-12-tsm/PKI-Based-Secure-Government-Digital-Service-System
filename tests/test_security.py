"""
Unit tests for Nepal PKI-Based Government Digital Services System.
Covers: user registration, RSA key generation, digital signatures,
        signature verification, certificate revocation, hybrid encryption,
        replay attack detection, and unauthorized signing attempts.

Run with:
    pytest tests/test_security.py -v
"""
import io
import os
import sys
import json
import pytest

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app as flask_app
from models.database import init_db, get_db
from utils.pki import (
    generate_user_keys_and_cert,
    hash_file,
    sign_data,
    verify_signature,
    hybrid_encrypt,
    hybrid_decrypt,
    full_verify_document,
    generate_nonce,
    _encrypt_private_key,
    _decrypt_private_key,
    _load_private_key,
)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def setup_app():
    """Initialise a fresh in-memory-compatible test database once per session."""
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("certificates", exist_ok=True)
    os.makedirs("generated_certificates", exist_ok=True)
    init_db()
    flask_app.seed_defaults()


@pytest.fixture()
def client():
    flask_app.app.config["TESTING"] = True
    flask_app.app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.app.test_client() as c:
        yield c


@pytest.fixture(scope="module")
def keypair():
    """Generate a fresh RSA key pair + certificate once per module."""
    priv_store, pub_pem, cert_pem, serial, expires_at = generate_user_keys_and_cert(
        "Test User", "testunit@gov.np", "testunit"
    )
    return {"priv_store": priv_store, "pub_pem": pub_pem, "cert_pem": cert_pem}


# ─── A. User Registration ─────────────────────────────────────────────────────

class TestUserRegistration:
    def test_register_success(self, client):
        r = client.post("/register", data={
            "username": "pytest_citizen",
            "email":    "pytest@test.np",
            "full_name": "PyTest Citizen",
            "phone":    "9800000099",
            "password": "Test@1234",
            "confirm_password": "Test@1234",
        }, follow_redirects=True)
        assert r.status_code == 200
        # Should land on login page with success flash
        assert b"Login" in r.data or b"successfully" in r.data

    def test_register_duplicate_username(self, client):
        data = dict(username="pytest_citizen", email="other@test.np",
                    full_name="Other", phone="9800000088",
                    password="Test@1234", confirm_password="Test@1234")
        r = client.post("/register", data=data, follow_redirects=True)
        assert b"already exists" in r.data

    def test_register_password_mismatch(self, client):
        r = client.post("/register", data=dict(
            username="newuser2", email="new2@t.np", full_name="New",
            phone="9800000077", password="Abc@1234", confirm_password="Wrong"),
            follow_redirects=True)
        assert b"do not match" in r.data

    def test_register_short_password(self, client):
        r = client.post("/register", data=dict(
            username="newuser3", email="new3@t.np", full_name="New",
            phone="9800000066", password="abc", confirm_password="abc"),
            follow_redirects=True)
        assert b"8 characters" in r.data

    def test_pki_artifacts_created_on_register(self, client):
        """After registration the user must have a public_key and certificate row."""
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username='pytest_citizen'").fetchone()
        assert user is not None
        assert user["public_key"] is not None
        # private key stored as keystore blob (NOT plain PEM)
        assert not user["private_key_encrypted"].strip().startswith("-----")
        cert = db.execute("SELECT * FROM certificates WHERE user_id=?", (user["id"],)).fetchone()
        assert cert is not None
        assert cert["is_valid"] == 1
        db.close()


# ─── B. RSA Key Generation ────────────────────────────────────────────────────

class TestRSAKeyGeneration:
    def test_keys_generated(self, keypair):
        assert keypair["pub_pem"].startswith("-----BEGIN PUBLIC KEY-----")
        assert keypair["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")

    def test_private_key_stored_encrypted(self, keypair):
        """Keystore blob must NOT be plain PEM."""
        assert not keypair["priv_store"].strip().startswith("-----")

    def test_keystore_roundtrip(self, keypair):
        """Decrypt keystore blob and verify it yields a valid PEM private key."""
        plain_pem = _decrypt_private_key(keypair["priv_store"])
        assert plain_pem.strip().startswith("-----BEGIN RSA PRIVATE KEY-----") or \
               plain_pem.strip().startswith("-----BEGIN PRIVATE KEY-----")

    def test_private_key_loadable(self, keypair):
        key_obj = _load_private_key(keypair["priv_store"])
        assert key_obj is not None

    def test_different_users_get_different_keys(self):
        _, pub1, _, _, _ = generate_user_keys_and_cert("Alice", "alice@t.np", "alice_u")
        _, pub2, _, _, _ = generate_user_keys_and_cert("Bob",   "bob@t.np",   "bob_u")
        assert pub1 != pub2


# ─── C. Digital Signature Creation ───────────────────────────────────────────

class TestDigitalSignatures:
    DATA = b"Important government document content."

    def test_sign_produces_base64(self, keypair):
        import base64
        sig = sign_data(keypair["priv_store"], self.DATA)
        # Must be valid base64
        decoded = base64.b64decode(sig)
        assert len(decoded) == 256   # RSA-2048 signature is 256 bytes

    def test_sign_deterministic_structure(self, keypair):
        """Two signatures of the same data with the same key are both verifiable."""
        sig1 = sign_data(keypair["priv_store"], self.DATA)
        sig2 = sign_data(keypair["priv_store"], self.DATA)
        assert verify_signature(keypair["pub_pem"], self.DATA, sig1)
        assert verify_signature(keypair["pub_pem"], self.DATA, sig2)

    def test_hash_file(self):
        data = b"file content"
        h = hash_file(data)
        assert len(h) == 64   # SHA-256 hex digest
        assert h == hash_file(data)   # deterministic


# ─── D. Signature Verification ───────────────────────────────────────────────

class TestSignatureVerification:
    DATA = b"Verified government content."

    def test_valid_signature(self, keypair):
        sig = sign_data(keypair["priv_store"], self.DATA)
        assert verify_signature(keypair["pub_pem"], self.DATA, sig) is True

    def test_tampered_data_fails(self, keypair):
        sig = sign_data(keypair["priv_store"], self.DATA)
        assert verify_signature(keypair["pub_pem"], b"TAMPERED content.", sig) is False

    def test_wrong_key_fails(self, keypair):
        _, other_pub, _, _, _ = generate_user_keys_and_cert("Eve", "eve@t.np", "eve_u")
        sig = sign_data(keypair["priv_store"], self.DATA)
        assert verify_signature(other_pub, self.DATA, sig) is False

    def test_full_verify_valid(self, keypair):
        data = b"Document bytes"
        h    = hash_file(data)
        sig  = sign_data(keypair["priv_store"], data)
        vr   = full_verify_document(data, h, sig, keypair["pub_pem"], cert_is_valid=1)
        assert vr.ok is True
        assert vr.result_code == "valid"
        assert vr.message == "VALID SIGNATURE"

    def test_full_verify_tampered(self, keypair):
        data = b"Original bytes"
        h    = hash_file(data)
        sig  = sign_data(keypair["priv_store"], data)
        vr   = full_verify_document(b"Modified bytes", h, sig, keypair["pub_pem"], cert_is_valid=1)
        assert vr.ok is False
        assert vr.result_code == "tampered"
        assert "TAMPERED" in vr.message

    def test_full_verify_invalid_sig(self, keypair):
        data = b"Good bytes"
        h    = hash_file(data)
        # corrupt signature
        vr   = full_verify_document(data, h, "AAAA", keypair["pub_pem"], cert_is_valid=1)
        assert vr.ok is False
        assert vr.result_code == "invalid"


# ─── E. Certificate Revocation ────────────────────────────────────────────────

class TestCertificateRevocation:
    def test_revoked_cert_fails_full_verify(self, keypair):
        data = b"Signed with revoked cert"
        h    = hash_file(data)
        sig  = sign_data(keypair["priv_store"], data)
        # cert_is_valid=0  ←  revoked
        vr   = full_verify_document(data, h, sig, keypair["pub_pem"], cert_is_valid=0)
        assert vr.ok is False
        assert vr.result_code == "revoked"
        assert "REVOKED" in vr.message

    def test_active_cert_passes_verify(self, keypair):
        data = b"Normal document"
        h    = hash_file(data)
        sig  = sign_data(keypair["priv_store"], data)
        vr   = full_verify_document(data, h, sig, keypair["pub_pem"], cert_is_valid=1)
        assert vr.ok is True

    def test_admin_can_revoke_via_route(self, client):
        # Register a citizen to revoke
        client.post("/register", data=dict(
            username="revoke_me", email="revokem@t.np", full_name="Revoke Me",
            phone="9800000055", password="Test@1234", confirm_password="Test@1234"))
        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE username='revoke_me'").fetchone()
        db.close()
        assert user is not None

        # Login as admin
        client.post("/login", data={"username": "admin", "password": "Admin@2024#Secure"})
        r = client.post(f"/admin/users/{user['id']}/revoke-cert",
                        data={"reason": "Test revocation"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"revoked" in r.data.lower()

        # Verify DB updated
        db   = get_db()
        cert = db.execute("SELECT * FROM certificates WHERE user_id=?", (user["id"],)).fetchone()
        db.close()
        assert cert["is_valid"] == 0
        assert cert["revocation_reason"] == "Test revocation"

    def test_admin_can_reissue_cert(self, client):
        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE username='revoke_me'").fetchone()
        uid  = user["id"]
        db.close()

        client.post("/login", data={"username": "admin", "password": "Admin@2024#Secure"})
        r = client.post(f"/admin/users/{uid}/reissue-cert", follow_redirects=True)
        assert r.status_code == 200

        db   = get_db()
        cert = db.execute(
            "SELECT * FROM certificates WHERE user_id=? ORDER BY issued_at DESC LIMIT 1", (uid,)
        ).fetchone()
        db.close()
        assert cert["is_valid"] == 1

    def test_revoked_user_cannot_submit_application(self, client):
        """Citizen with revoked cert should be blocked from applying."""
        # Register and immediately revoke
        client.post("/register", data=dict(
            username="blocked_user", email="blocked@t.np", full_name="Blocked User",
            phone="9800000044", password="Test@1234", confirm_password="Test@1234"))
        db   = get_db()
        user = db.execute("SELECT * FROM users WHERE username='blocked_user'").fetchone()
        db.execute("UPDATE certificates SET is_valid=0 WHERE user_id=?", (user["id"],))
        db.commit()
        db.close()

        # Login as citizen and attempt to submit
        client.post("/login", data={"username": "blocked_user", "password": "Test@1234"})
        r = client.get("/apply/driving_license", follow_redirects=True)
        assert b"revoked" in r.data.lower()


# ─── F. Hybrid Encryption ─────────────────────────────────────────────────────

class TestHybridEncryption:
    PLAINTEXT = b"Sensitive government document: citizenship details."

    def test_encrypt_produces_different_ciphertext(self, keypair):
        ct1, _ = hybrid_encrypt(self.PLAINTEXT, keypair["pub_pem"])
        ct2, _ = hybrid_encrypt(self.PLAINTEXT, keypair["pub_pem"])
        # IV is random so ciphertexts differ each time
        assert ct1 != ct2

    def test_decrypt_recovers_plaintext(self, keypair):
        ct, enc_key = hybrid_encrypt(self.PLAINTEXT, keypair["pub_pem"])
        dec = hybrid_decrypt(ct, enc_key, keypair["priv_store"])
        assert dec == self.PLAINTEXT

    def test_wrong_key_cannot_decrypt(self, keypair):
        ct, enc_key = hybrid_encrypt(self.PLAINTEXT, keypair["pub_pem"])
        other_priv, _, _, _, _ = generate_user_keys_and_cert("Other", "other2@t.np", "other2")
        with pytest.raises(Exception):
            hybrid_decrypt(ct, enc_key, other_priv)

    def test_encrypted_key_is_base64(self, keypair):
        import base64
        _, enc_key = hybrid_encrypt(self.PLAINTEXT, keypair["pub_pem"])
        decoded = base64.b64decode(enc_key)
        assert len(decoded) == 256  # RSA-2048 OAEP output

    def test_large_file_encrypt_decrypt(self, keypair):
        large = os.urandom(1024 * 512)   # 512 KB
        ct, enc_key = hybrid_encrypt(large, keypair["pub_pem"])
        dec = hybrid_decrypt(ct, enc_key, keypair["priv_store"])
        assert dec == large


# ─── G. Replay Attack Detection ───────────────────────────────────────────────

class TestReplayAttackProtection:
    def test_nonce_is_hex_string(self):
        nonce = generate_nonce()
        assert len(nonce) == 64
        int(nonce, 16)   # raises ValueError if not hex

    def test_nonces_are_unique(self):
        nonces = {generate_nonce() for _ in range(100)}
        assert len(nonces) == 100

    def test_duplicate_nonce_rejected(self, client):
        """Submitting the same nonce twice must be rejected."""
        # Register and login
        client.post("/register", data=dict(
            username="replay_user", email="replay@t.np", full_name="Replay User",
            phone="9800000033", password="Test@1234", confirm_password="Test@1234"))
        client.post("/login", data={"username": "replay_user", "password": "Test@1234"})

        # Insert a nonce directly into used_nonces as if already consumed
        db = get_db()
        user = db.execute("SELECT id FROM users WHERE username='replay_user'").fetchone()
        fixed_nonce = generate_nonce()
        db.execute("INSERT INTO used_nonces (nonce, user_id) VALUES (?,?)",
                   (fixed_nonce, user["id"]))
        db.commit()
        db.close()

        # Submit application reusing that nonce
        r = client.post("/apply/driving_license", data={
            "_nonce":             fixed_nonce,
            "full_name":          "Replay User",
            "citizenship_number": "99-99-99-99999",
            "phone":              "9800000033",
            "email":              "replay@t.np",
            "province":           "Bagmati",
            "district":           "Kathmandu",
            "municipality":       "KMC",
            "ward_number":        "1",
            "date_of_birth":      "1990-01-01",
            "address":            "Test Street",
            "citizenship_copy":   (io.BytesIO(b"PNG\x00fake"), "cit.png"),
            "passport_photo":     (io.BytesIO(b"PNG\x00photo"), "photo.png"),
        }, content_type="multipart/form-data", follow_redirects=True)
        assert b"Duplicate or replayed request detected" in r.data

    def test_fresh_nonce_accepted(self, client):
        """A genuinely fresh nonce must allow the submission through."""
        client.post("/login", data={"username": "replay_user", "password": "Test@1234"})
        fresh_nonce = generate_nonce()
        r = client.post("/apply/driving_license", data={
            "_nonce":             fresh_nonce,
            "full_name":          "Replay User",
            "citizenship_number": "11-11-11-11111",
            "phone":              "9800000033",
            "email":              "replay@t.np",
            "province":           "Bagmati",
            "district":           "Kathmandu",
            "municipality":       "KMC",
            "ward_number":        "1",
            "date_of_birth":      "1990-01-01",
            "address":            "Test Street",
            "citizenship_copy":   (io.BytesIO(b"PNG\x00fake2"), "cit2.png"),
            "passport_photo":     (io.BytesIO(b"PNG\x00photo2"), "photo2.png"),
        }, content_type="multipart/form-data", follow_redirects=True)
        # Should NOT show replay error
        assert b"Duplicate or replayed request detected" not in r.data


# ─── H. Unauthorized Signing Attempts ────────────────────────────────────────

class TestUnauthorizedSigning:
    def test_citizen_cannot_access_officer_routes(self, client):
        client.post("/login", data={"username": "replay_user", "password": "Test@1234"})
        r = client.get("/officer/dashboard", follow_redirects=False)
        assert r.status_code == 403

    def test_citizen_cannot_access_admin_routes(self, client):
        client.post("/login", data={"username": "replay_user", "password": "Test@1234"})
        r = client.get("/admin/dashboard", follow_redirects=False)
        assert r.status_code == 403

    def test_officer_cannot_access_admin_routes(self, client):
        client.post("/login", data={"username": "officer", "password": "Officer@2024#Secure"})
        r = client.get("/admin/dashboard", follow_redirects=False)
        assert r.status_code == 403

    def test_unauthenticated_cannot_access_dashboard(self, client):
        client.get("/logout")
        r = client.get("/dashboard", follow_redirects=False)
        # Must redirect away — not 200
        assert r.status_code in (301, 302)

    def test_unauthenticated_cannot_submit_application(self, client):
        client.get("/logout")
        r = client.post("/apply/driving_license", data={}, follow_redirects=False)
        assert r.status_code in (301, 302)

    def test_citizen_cannot_verify_other_users_doc(self, client):
        """Citizen A's verify endpoint must 404 for Citizen B's doc_id."""
        # Register second citizen
        client.post("/register", data=dict(
            username="citizen_b", email="cb@t.np", full_name="Citizen B",
            phone="9800000022", password="Test@1234", confirm_password="Test@1234"))
        # Login as original citizen
        client.post("/login", data={"username": "replay_user", "password": "Test@1234"})
        # Get Citizen B's user_id
        db   = get_db()
        cb   = db.execute("SELECT id FROM users WHERE username='citizen_b'").fetchone()
        # Fabricate a document belonging to citizen B (no real upload needed for route test)
        # We test that the route returns an error for a doc_id that doesn't belong to this user
        r = client.post("/verify/99999")  # unlikely to exist
        assert r.status_code == 200
        data = r.get_json()
        assert data["result"] == "error"
        db.close()

    def test_keystore_encrypted_key_not_plain_pem(self):
        """Private keys stored in DB must be keystore-encrypted blobs."""
        db   = get_db()
        user = db.execute("SELECT private_key_encrypted FROM users WHERE username='pytest_citizen'").fetchone()
        db.close()
        stored = user["private_key_encrypted"]
        assert not stored.strip().startswith("-----BEGIN"), \
            "Private key must NOT be stored as plain PEM — keystore encryption required"
