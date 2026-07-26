# Nepal PKI-Based Government Digital Services

A complete Flask web application demonstrating **Public Key Infrastructure (PKI)** for a Government Digital Services platform. Built as an academic cybersecurity project.

---

## Features

- **RSA 2048-bit** key pair generation per citizen / officer
- **Encrypted Keystore** — private keys are AES-256 encrypted at rest (D)
- **Digital Certificates** issued by a Nepal Government Root CA
- **SHA-256** document hashing
- **Digital Signatures** on all submitted documents
- **Hybrid Encryption** — AES-256 documents, RSA-OAEP encrypted AES key (B)
- **Certificate Revocation** — admin can revoke/reissue certificates (A)
- **Replay Attack Protection** — unique cryptographic nonce per submission (C)
- **Enhanced Signature Verification** — cert validity + revocation + hash + sig (E)
- **Approval Certificate PDF** — ReportLab-generated official PDF with QR code
- **Role-Based Access Control** — Citizen / Government Officer / Administrator
- **3 Government Services** — Driving License, Business Registration, Tax Filing
- **Nepal Administrative Data** — Provinces → Districts
- **Audit Logging** — all system actions recorded

---

## Requirements

- Python 3.8+
- pip

---

## Installation

```bash
unzip pki_gov_project.zip
cd pki_gov
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
pip install -r requirements.txt
```

---

## Running the Application

```bash
python app.py
```

Open: **http://localhost:5000**

The app auto-creates `database.db`, the Root CA key pair in `certificates/`, and seeds default accounts on first run.

---

## Default Credentials

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Admin@2024#Secure` |
| Government Officer | `officer` | `Officer@2024#Secure` |
| Citizen | Register at `/register` | — |

---

## Running Unit Tests (F)

```bash
pip install pytest
pytest tests/test_security.py -v
```

Tests cover:
- User registration
- RSA key generation & keystore encryption
- Digital signature creation
- Signature verification (valid / tampered / invalid)
- Certificate revocation detection
- Hybrid AES-256 + RSA-OAEP encryption/decryption
- Replay attack detection (duplicate nonce rejection)
- Unauthorized signing / route access attempts

---

## PKI Workflow

```
1. REGISTRATION
   ├── RSA 2048-bit key pair generated
   ├── Private key AES-256 encrypted → stored in DB keystore (D)
   ├── Certificate signed by Nepal Gov Root CA
   └── Public key + Certificate stored in DB

2. APPLICATION SUBMISSION (Replay Protection — C)
   ├── Fresh cryptographic nonce generated per form load
   ├── Nonce checked against used_nonces table
   ├── Certificate revocation status checked before signing
   ├── Each document: SHA-256 hash computed → RSA signature created
   ├── Document AES-256 encrypted, AES key RSA-OAEP encrypted (B)
   └── Application payload signed + hash stored

3. VERIFICATION (E — all checks in order)
   ├── 1. Certificate validity & revocation status
   ├── 2. AES-256 document decryption
   ├── 3. SHA-256 hash comparison (integrity)
   └── 4. RSA signature verification
        ↓
   VALID SIGNATURE | INVALID SIGNATURE | DOCUMENT HAS BEEN TAMPERED | CERTIFICATE REVOKED
```

---

## Hybrid Encryption Workflow (B)

```
ENCRYPT (on upload):
  plaintext → AES-256-CBC(random key, random IV) → ciphertext
  AES key   → RSA-OAEP(citizen public key)       → enc_aes_key
  Store: ciphertext + enc_aes_key in DB / disk

DECRYPT (on download):
  enc_aes_key → RSA-OAEP decrypt(citizen private key) → AES key
  ciphertext  → AES-256-CBC decrypt(AES key, IV)       → plaintext
```

---

## Certificate Revocation (A)

```
Admin panel → User Detail → Revoke Certificate
  ├── certificates.is_valid set to 0
  ├── revoked_at, revoked_by, revocation_reason stored
  └── All future verification returns "CERTIFICATE REVOKED"

Admin panel → User Detail → Re-issue Certificate
  ├── New RSA key pair generated
  ├── New certificate signed by Root CA
  └── Old certificate marked invalid
```

Revoked users cannot:
- Submit new applications (blocked at route level)
- Have documents verified as valid (full_verify_document returns `revoked`)

---

## Replay Attack Protection (C)

```
1. Server generates a 256-bit hex nonce on each form load
2. Nonce embedded as hidden field in the service form
3. On POST:
   a. Nonce checked against used_nonces table
   b. If found → reject with "Duplicate or replayed request detected."
   c. If new  → insert into used_nonces, proceed with submission
4. Nonce also stored on the application record for audit
```

---

## Secure Key Management (D)

Private keys are never stored as plain PEM text. On generation:

```
plain_pem → AES-256-CBC(master_key, random_IV) → base64(IV + ciphertext)
```

The master key is derived from `PKI_MASTER_KEY` environment variable (falls back to a built-in default for development). Set it in production:

```bash
export PKI_MASTER_KEY="your-256-bit-secret"
```

Keys are decrypted in memory only during signing operations and are never exposed in the UI or logs.

---

## Project Structure

```
pki_gov/
├── app.py                      # Main Flask application
├── requirements.txt
├── README.md
├── database.db                 # SQLite (auto-created)
├── models/
│   └── database.py             # Schema + migration
├── utils/
│   ├── pki.py                  # RSA, AES, signing, verification, keystore
│   ├── helpers.py              # File upload, Nepal data, audit logging
│   └── certificate_gen.py     # ReportLab PDF approval certificates
├── tests/
│   └── test_security.py       # pytest unit tests (F)
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html / register.html
│   ├── citizen/
│   ├── officer/
│   ├── admin/
│   └── errors/
├── static/css/ static/js/
├── uploads/                    # AES-256 encrypted document storage
├── certificates/               # Root CA key + cert
└── generated_certificates/     # PDF approval certificates
```
