import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database.db')

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            phone TEXT,
            role TEXT DEFAULT 'citizen',
            public_key TEXT,
            private_key_encrypted TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            certificate_pem TEXT NOT NULL,
            serial_number TEXT NOT NULL,
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_valid INTEGER DEFAULT 1,
            revoked_at TIMESTAMP,
            revoked_by INTEGER,
            revocation_reason TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (revoked_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            service_type TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            form_data TEXT NOT NULL,
            signature TEXT,
            hash_value TEXT,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            admin_notes TEXT,
            tracking_number TEXT UNIQUE,
            nonce TEXT UNIQUE,
            payment_status TEXT DEFAULT 'unpaid',
            payment_method TEXT,
            transaction_id TEXT,
            paid_at TIMESTAMP,
            additional_docs_requested INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            document_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            file_size INTEGER,
            mime_type TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_verified INTEGER DEFAULT 0,
            verification_result TEXT,
            encrypted_aes_key TEXT,
            is_encrypted INTEGER DEFAULT 0,
            FOREIGN KEY (application_id) REFERENCES applications(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS approval_certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER NOT NULL UNIQUE,
            certificate_number TEXT NOT NULL UNIQUE,
            pdf_filename TEXT NOT NULL,
            officer_id INTEGER NOT NULL,
            officer_name TEXT NOT NULL,
            issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (application_id) REFERENCES applications(id),
            FOREIGN KEY (officer_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS used_nonces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nonce TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    conn.commit()
    _migrate(conn)
    conn.close()

def _migrate(conn):
    c = conn.cursor()
    migrations = [
        ("certificates", "revoked_at",              "ALTER TABLE certificates ADD COLUMN revoked_at TIMESTAMP"),
        ("certificates", "revoked_by",               "ALTER TABLE certificates ADD COLUMN revoked_by INTEGER"),
        ("certificates", "revocation_reason",        "ALTER TABLE certificates ADD COLUMN revocation_reason TEXT"),
        ("applications", "nonce",                    "ALTER TABLE applications ADD COLUMN nonce TEXT"),
        ("applications", "payment_status",           "ALTER TABLE applications ADD COLUMN payment_status TEXT DEFAULT 'unpaid'"),
        ("applications", "payment_method",           "ALTER TABLE applications ADD COLUMN payment_method TEXT"),
        ("applications", "transaction_id",           "ALTER TABLE applications ADD COLUMN transaction_id TEXT"),
        ("applications", "paid_at",                  "ALTER TABLE applications ADD COLUMN paid_at TIMESTAMP"),
        ("applications", "additional_docs_requested","ALTER TABLE applications ADD COLUMN additional_docs_requested INTEGER DEFAULT 0"),
        ("documents",    "encrypted_aes_key",        "ALTER TABLE documents ADD COLUMN encrypted_aes_key TEXT"),
        ("documents",    "is_encrypted",             "ALTER TABLE documents ADD COLUMN is_encrypted INTEGER DEFAULT 0"),
    ]
    existing = {}
    for table, col, sql in migrations:
        if table not in existing:
            cols = [row[1] for row in c.execute(f"PRAGMA table_info({table})").fetchall()]
            existing[table] = cols
        if col not in existing[table]:
            try:
                c.execute(sql)
                existing[table].append(col)
            except Exception:
                pass
    conn.commit()
