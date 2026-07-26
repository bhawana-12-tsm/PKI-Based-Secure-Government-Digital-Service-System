import os
import json
import secrets
from datetime import datetime
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, send_from_directory, abort,
                   make_response, send_file)
from werkzeug.security import generate_password_hash, check_password_hash

from models.database import get_db, init_db
from utils.pki import (generate_user_keys_and_cert, hash_file, sign_data,
                        sign_application, verify_signature,
                        hybrid_encrypt, hybrid_decrypt,
                        full_verify_document, generate_nonce)
from utils.helpers import (allowed_file, generate_tracking_number,
                            save_uploaded_file, NEPAL_PROVINCES, log_action,
                            UPLOAD_FOLDER)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'nepal-gov-pki-secret-2024-xk92pls')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

CERTS_FOLDER = os.path.join(os.path.dirname(__file__), 'generated_certificates')

# ─── No-cache helper ──────────────────────────────────────────────────────────

def no_cache(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma']  = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# ─── Auth decorators ──────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return no_cache(make_response(f(*args, **kwargs)))
    return decorated

def citizen_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        if session.get('role') != 'citizen':
            abort(403)
        return no_cache(make_response(f(*args, **kwargs)))
    return decorated

def officer_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        if session.get('role') != 'officer':
            abort(403)
        return no_cache(make_response(f(*args, **kwargs)))
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('index'))
        if session.get('role') != 'admin':
            abort(403)
        return no_cache(make_response(f(*args, **kwargs)))
    return decorated

# ─── Public routes ────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        role = session.get('role')
        if role == 'admin':   return redirect(url_for('admin_dashboard'))
        if role == 'officer': return redirect(url_for('officer_dashboard'))
        return redirect(url_for('citizen_dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username  = request.form.get('username', '').strip()
        email     = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        phone     = request.form.get('phone', '').strip()
        password  = request.form.get('password', '')
        confirm   = request.form.get('confirm_password', '')

        if not all([username, email, full_name, phone, password, confirm]):
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return render_template('register.html')

        db = get_db()
        if db.execute('SELECT id FROM users WHERE username=? OR email=?', (username, email)).fetchone():
            flash('Username or email already exists.', 'danger')
            db.close()
            return render_template('register.html')

        priv_store, pub_pem, cert_pem, serial, expires_at = \
            generate_user_keys_and_cert(full_name, email, username)
        pw_hash = generate_password_hash(password)
        cur = db.execute(
            'INSERT INTO users (username, email, password_hash, full_name, phone, public_key, private_key_encrypted) '
            'VALUES (?,?,?,?,?,?,?)',
            (username, email, pw_hash, full_name, phone, pub_pem, priv_store)
        )
        user_id = cur.lastrowid
        db.execute(
            'INSERT INTO certificates (user_id, certificate_pem, serial_number, expires_at) VALUES (?,?,?,?)',
            (user_id, cert_pem, serial, expires_at)
        )
        db.commit()
        log_action(db, user_id, 'REGISTER', f'New citizen registered: {username}', request.remote_addr)
        db.close()
        flash('Registration successful! Your digital certificate has been issued. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db   = get_db()
        user = db.execute('SELECT * FROM users WHERE username=? AND is_active=1', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id']   = user['id']
            session['username']  = user['username']
            session['full_name'] = user['full_name']
            session['role']      = user['role']
            log_action(db, user['id'], 'LOGIN', f'User logged in: {username}', request.remote_addr)
            db.close()
            flash(f'Welcome back, {user["full_name"]}!', 'success')
            role = user['role']
            if role == 'admin':   return redirect(url_for('admin_dashboard'))
            if role == 'officer': return redirect(url_for('officer_dashboard'))
            return redirect(url_for('citizen_dashboard'))
        db.close()
        flash('Invalid username or password.', 'danger')
    return no_cache(make_response(render_template('login.html')))

@app.route('/logout')
def logout():
    if 'user_id' in session:
        db = get_db()
        log_action(db, session['user_id'], 'LOGOUT',
                   f'User logged out: {session["username"]}', request.remote_addr)
        db.close()
    session.clear()
    flash('You have been logged out.', 'info')
    return no_cache(make_response(redirect(url_for('index'))))

# ─── Citizen routes ───────────────────────────────────────────────────────────

@app.route('/dashboard')
@citizen_required
def citizen_dashboard():
    db  = get_db()
    uid = session['user_id']
    apps = db.execute('SELECT * FROM applications WHERE user_id=? ORDER BY submitted_at DESC', (uid,)).fetchall()
    total        = len(apps)
    pending      = sum(1 for a in apps if a['status'] == 'pending')
    under_review = sum(1 for a in apps if a['status'] == 'under_review')
    approved     = sum(1 for a in apps if a['status'] == 'approved')
    rejected     = sum(1 for a in apps if a['status'] == 'rejected')
    docs = db.execute('SELECT COUNT(*) as cnt FROM documents WHERE user_id=?', (uid,)).fetchone()['cnt']
    recent = apps[:5]
    cert_map = {}
    for a in recent:
        ac = db.execute('SELECT * FROM approval_certificates WHERE application_id=?', (a['id'],)).fetchone()
        if ac:
            cert_map[a['id']] = ac
    notifications = []
    for a in apps[:5]:
        if a['status'] == 'approved':
            notifications.append({'type': 'success', 'msg': f'Application {a["tracking_number"]} has been approved!'})
        elif a['status'] == 'rejected':
            notifications.append({'type': 'danger',  'msg': f'Application {a["tracking_number"]} was rejected.'})
        elif a['status'] == 'under_review':
            notifications.append({'type': 'info',    'msg': f'Application {a["tracking_number"]} is under review.'})
        elif a['additional_docs_requested']:
            notifications.append({'type': 'warning', 'msg': f'Application {a["tracking_number"]} requires additional documents.'})
    db.close()
    return render_template('citizen/dashboard.html',
                           stats={'total': total, 'pending': pending, 'under_review': under_review,
                                  'approved': approved, 'rejected': rejected, 'docs': docs},
                           recent_apps=recent, notifications=notifications, cert_map=cert_map)

@app.route('/profile', methods=['GET', 'POST'])
@citizen_required
def profile():
    db  = get_db()
    uid = session['user_id']
    user = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    cert = db.execute('SELECT * FROM certificates WHERE user_id=? ORDER BY issued_at DESC LIMIT 1', (uid,)).fetchone()
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        phone     = request.form.get('phone', '').strip()
        db.execute('UPDATE users SET full_name=?, phone=? WHERE id=?', (full_name, phone, uid))
        db.commit()
        session['full_name'] = full_name
        log_action(db, uid, 'PROFILE_UPDATE', 'User updated profile', request.remote_addr)
        flash('Profile updated successfully.', 'success')
        db.close()
        return redirect(url_for('profile'))
    db.close()
    return render_template('citizen/profile.html', user=user, cert=cert)

@app.route('/apply/<service_type>', methods=['GET', 'POST'])
@citizen_required
def apply_service(service_type):
    valid_services = ['driving_license', 'business_registration', 'tax_filing']
    if service_type not in valid_services:
        abort(404)
    db  = get_db()
    uid = session['user_id']

    cert = db.execute(
        'SELECT is_valid FROM certificates WHERE user_id=? ORDER BY issued_at DESC LIMIT 1', (uid,)
    ).fetchone()
    if cert and not cert['is_valid']:
        db.close()
        flash('Your digital certificate has been revoked. You cannot submit new applications.', 'danger')
        return redirect(url_for('citizen_dashboard'))

    if request.method == 'POST':
        nonce = request.form.get('_nonce', '').strip()
        if not nonce:
            flash('Invalid form submission. Please reload the page and try again.', 'danger')
            db.close()
            return render_template(f'citizen/services/{service_type}.html',
                                   form_data={}, provinces=NEPAL_PROVINCES, nonce=generate_nonce())

        existing_nonce = db.execute('SELECT id FROM used_nonces WHERE nonce=?', (nonce,)).fetchone()
        if existing_nonce:
            log_action(db, uid, 'REPLAY_ATTACK', f'Duplicate nonce: {nonce[:16]}', request.remote_addr)
            db.close()
            flash('Duplicate or replayed request detected.', 'danger')
            return redirect(url_for('citizen_dashboard'))

        db.execute('INSERT INTO used_nonces (nonce, user_id) VALUES (?,?)', (nonce, uid))
        db.commit()

        form_data  = {k: v for k, v in request.form.items() if k != '_nonce'}
        doc_fields = _get_doc_fields(service_type)
        uploaded_docs = {}

        for field_name, label in doc_fields.items():
            if field_name not in request.files or request.files[field_name].filename == '':
                flash(f'{label} is required.', 'danger')
                db.close()
                return render_template(f'citizen/services/{service_type}.html',
                                       form_data=form_data, provinces=NEPAL_PROVINCES, nonce=generate_nonce())
            file = request.files[field_name]
            if not allowed_file(file.filename):
                flash(f'{label}: only PNG, JPG, PDF allowed.', 'danger')
                db.close()
                return render_template(f'citizen/services/{service_type}.html',
                                       form_data=form_data, provinces=NEPAL_PROVINCES, nonce=generate_nonce())
            uploaded_docs[field_name] = (file, label)

        # Save application and documents to DB immediately (payment_status='unpaid').
        # We never put file bytes in the session cookie — that silently overflows
        # Flask's 4 KB signed-cookie limit and loses the data entirely.
        user = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
        tracking = generate_tracking_number(service_type)
        cur = db.execute(
            'INSERT INTO applications '
            '(user_id, service_type, form_data, tracking_number, status, nonce, '
            'payment_status, submitted_at) '
            'VALUES (?,?,?,?,?,?,?,?)',
            (uid, service_type, json.dumps(form_data), tracking, 'pending', nonce,
             'unpaid', datetime.utcnow().isoformat())
        )
        app_id = cur.lastrowid
        db.commit()

        private_key_store = user['private_key_encrypted']
        public_key_pem    = user['public_key']
        doc_hashes = {}

        for field_name, (file, label) in uploaded_docs.items():
            file.seek(0)
            unique_name, file_bytes = save_uploaded_file(file, uid, app_id)
            file_hash = hash_file(file_bytes)
            doc_sig   = sign_data(private_key_store, file_bytes)
            doc_hashes[field_name] = file_hash
            mime = file.content_type or 'application/octet-stream'
            ciphertext, enc_aes_key = hybrid_encrypt(file_bytes, public_key_pem)
            filepath = os.path.join(UPLOAD_FOLDER, unique_name)
            with open(filepath, 'wb') as fh:
                fh.write(ciphertext)
            db.execute(
                'INSERT INTO documents '
                '(application_id, user_id, document_type, filename, original_filename, '
                'file_hash, signature, file_size, mime_type, encrypted_aes_key, is_encrypted) '
                'VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                (app_id, uid, label, unique_name, file.filename,
                 file_hash, doc_sig, len(file_bytes), mime, enc_aes_key, 1)
            )

        signature, data_hash, payload = sign_application(private_key_store, form_data, doc_hashes)
        db.execute('UPDATE applications SET signature=?, hash_value=? WHERE id=?',
                   (signature, data_hash, app_id))
        db.commit()
        log_action(db, uid, 'DOCUMENT_SIGN',
                   f'Documents PKI-signed for pending application {tracking}', request.remote_addr)
        db.close()

        # Only store the tiny app_id — never file bytes — in the session cookie
        session['pending_app_id'] = app_id
        return redirect(url_for('payment_page', service_type=service_type))

    new_nonce = generate_nonce()
    db.close()
    return render_template(f'citizen/services/{service_type}.html',
                           form_data={}, provinces=NEPAL_PROVINCES, nonce=new_nonce)

# ─── Payment routes ───────────────────────────────────────────────────────────

PAYMENT_AMOUNTS = {
    'driving_license':       'NPR 1,500',
    'business_registration': 'NPR 2,000',
    'tax_filing':            'NPR 500',
}

@app.route('/payment/<service_type>')
@citizen_required
def payment_page(service_type):
    app_id = session.get('pending_app_id')
    if not app_id:
        flash('No pending application found. Please fill the form first.', 'warning')
        return redirect(url_for('apply_service', service_type=service_type))
    # Verify the application belongs to this citizen and is still unpaid
    db  = get_db()
    uid = session['user_id']
    appl = db.execute(
        'SELECT * FROM applications WHERE id=? AND user_id=? AND payment_status=?',
        (app_id, uid, 'unpaid')
    ).fetchone()
    db.close()
    if not appl:
        session.pop('pending_app_id', None)
        flash('No pending application found. Please fill the form first.', 'warning')
        return redirect(url_for('apply_service', service_type=service_type))
    amount = PAYMENT_AMOUNTS.get(service_type, 'NPR 1,000')
    service_label = service_type.replace('_', ' ').title()
    return render_template('citizen/payment.html',
                           service_type=service_type,
                           service_label=service_label,
                           amount=amount)

@app.route('/payment/<service_type>/process', methods=['POST'])
@citizen_required
def process_payment(service_type):
    app_id = session.get('pending_app_id')
    if not app_id:
        flash('Session expired. Please fill the form again.', 'warning')
        return redirect(url_for('apply_service', service_type=service_type))

    db  = get_db()
    uid = session['user_id']
    appl = db.execute(
        'SELECT * FROM applications WHERE id=? AND user_id=? AND payment_status=?',
        (app_id, uid, 'unpaid')
    ).fetchone()
    if not appl:
        db.close()
        session.pop('pending_app_id', None)
        flash('Application not found or already paid. Please fill the form again.', 'warning')
        return redirect(url_for('apply_service', service_type=service_type))

    payment_method = request.form.get('payment_method', 'esewa')
    transaction_id = f"TXN-{secrets.token_hex(8).upper()}"

    # Update existing application record with payment info
    db.execute(
        'UPDATE applications SET payment_status=?, payment_method=?, transaction_id=?, paid_at=?, updated_at=? WHERE id=?',
        ('paid', payment_method, transaction_id, datetime.utcnow().isoformat(), datetime.utcnow().isoformat(), app_id)
    )
    db.commit()
    log_action(db, uid, 'PAYMENT',
               f'Payment via {payment_method}, TXN: {transaction_id} for app {appl["tracking_number"]}',
               request.remote_addr)
    log_action(db, uid, 'APPLICATION_SUBMIT',
               f'Application {appl["tracking_number"]} submitted after payment', request.remote_addr)
    db.close()

    session.pop('pending_app_id', None)

    return render_template('citizen/payment_success.html',
                           tracking_number=appl['tracking_number'],
                           transaction_id=transaction_id,
                           payment_method=payment_method,
                           service_label=service_type.replace('_', ' ').title())

def _get_doc_fields(service_type):
    return {
        'driving_license': {
            'citizenship_copy': 'Citizenship Certificate',
            'passport_photo':   'Passport Size Photo',
        },
        'business_registration': {
            'citizenship_copy': 'Citizenship Certificate',
            'business_plan':    'Business Plan',
            'rental_agreement': 'Rental Agreement / Ownership Document',
        },
        'tax_filing': {
            'citizenship_copy': 'Citizenship Certificate',
            'tax_form':         'Tax Filing Form',
            'income_statement': 'Income Statement',
        },
    }.get(service_type, {})

@app.route('/applications')
@citizen_required
def my_applications():
    db  = get_db()
    uid = session['user_id']
    apps = db.execute('SELECT * FROM applications WHERE user_id=? ORDER BY submitted_at DESC', (uid,)).fetchall()
    cert_map = {}
    for a in apps:
        ac = db.execute('SELECT * FROM approval_certificates WHERE application_id=?', (a['id'],)).fetchone()
        if ac:
            cert_map[a['id']] = ac
    db.close()
    return render_template('citizen/applications.html', applications=apps, cert_map=cert_map)

@app.route('/applications/<int:app_id>')
@citizen_required
def application_detail(app_id):
    db  = get_db()
    uid = session['user_id']
    appl = db.execute('SELECT * FROM applications WHERE id=? AND user_id=?', (app_id, uid)).fetchone()
    if not appl:
        abort(404)
    docs      = db.execute('SELECT * FROM documents WHERE application_id=?', (app_id,)).fetchall()
    form_data = json.loads(appl['form_data'])
    appr_cert = db.execute('SELECT * FROM approval_certificates WHERE application_id=?', (app_id,)).fetchone()
    db.close()
    return render_template('citizen/application_detail.html',
                           appl=appl, docs=docs, form_data=form_data, appr_cert=appr_cert)

@app.route('/certificate/download/<int:app_id>')
@citizen_required
def download_approval_cert(app_id):
    db  = get_db()
    uid = session['user_id']
    appl = db.execute('SELECT * FROM applications WHERE id=? AND user_id=?', (app_id, uid)).fetchone()
    if not appl:
        abort(404)
    ac = db.execute('SELECT * FROM approval_certificates WHERE application_id=?', (app_id,)).fetchone()
    db.close()
    if not ac:
        abort(404)
    return send_from_directory(CERTS_FOLDER, ac['pdf_filename'], as_attachment=True,
                                download_name=f"ApprovalCertificate_{appl['tracking_number']}.pdf")

@app.route('/verify')
@citizen_required
def verify_documents():
    db  = get_db()
    uid = session['user_id']
    docs = db.execute('''
        SELECT d.*, a.tracking_number, a.service_type FROM documents d
        JOIN applications a ON d.application_id = a.id
        WHERE d.user_id=? ORDER BY d.uploaded_at DESC
    ''', (uid,)).fetchall()
    db.close()
    return render_template('citizen/verify.html', documents=docs)

@app.route('/verify/<int:doc_id>', methods=['POST'])
@citizen_required
def verify_doc(doc_id):
    db  = get_db()
    uid = session['user_id']
    row = db.execute(
        'SELECT d.*, u.public_key, c.is_valid as cert_valid '
        'FROM documents d '
        'JOIN users u ON d.user_id=u.id '
        'LEFT JOIN certificates c ON c.user_id=u.id '
        'WHERE d.id=? AND d.user_id=? '
        'ORDER BY c.issued_at DESC LIMIT 1',
        (doc_id, uid)
    ).fetchone()
    if not row:
        return jsonify({'result': 'error', 'message': 'Document not found'})
    filepath = os.path.join(UPLOAD_FOLDER, row['filename'])
    try:
        with open(filepath, 'rb') as f:
            raw = f.read()
        if row['is_encrypted'] and row['encrypted_aes_key']:
            user = db.execute('SELECT private_key_encrypted FROM users WHERE id=?', (uid,)).fetchone()
            file_bytes = hybrid_decrypt(raw, row['encrypted_aes_key'], user['private_key_encrypted'])
        else:
            file_bytes = raw
        cert_valid = row['cert_valid'] if row['cert_valid'] is not None else 1
        vr = full_verify_document(file_bytes, row['file_hash'], row['signature'],
                                   row['public_key'], cert_valid)
        db.execute('UPDATE documents SET is_verified=1, verification_result=? WHERE id=?',
                   (vr.result_code, doc_id))
        db.commit()
        log_action(db, uid, 'VERIFY_SIGNATURE',
                   f'Document {doc_id} verified: {vr.result_code}', request.remote_addr)
        db.close()
        return jsonify({'result': vr.result_code, 'message': vr.message,
                        'hash': vr.details.get('current_hash', vr.details.get('hash', ''))})
    except Exception as e:
        db.close()
        return jsonify({'result': 'error', 'message': str(e)})

# ─── Government Officer routes ────────────────────────────────────────────────

@app.route('/officer/dashboard')
@officer_required
def officer_dashboard():
    db = get_db()
    total        = db.execute("SELECT COUNT(*) as c FROM applications").fetchone()['c']
    pending      = db.execute("SELECT COUNT(*) as c FROM applications WHERE status='pending'").fetchone()['c']
    under_review = db.execute("SELECT COUNT(*) as c FROM applications WHERE status='under_review'").fetchone()['c']
    approved     = db.execute("SELECT COUNT(*) as c FROM applications WHERE status='approved'").fetchone()['c']
    rejected     = db.execute("SELECT COUNT(*) as c FROM applications WHERE status='rejected'").fetchone()['c']
    recent_apps  = db.execute('''
        SELECT a.*, u.full_name, u.username FROM applications a
        JOIN users u ON a.user_id=u.id ORDER BY a.submitted_at DESC LIMIT 10
    ''').fetchall()
    db.close()
    return render_template('officer/dashboard.html',
        stats={'total': total, 'pending': pending, 'under_review': under_review,
               'approved': approved, 'rejected': rejected},
        recent_apps=recent_apps)

@app.route('/officer/applications')
@officer_required
def officer_applications():
    db  = get_db()
    status_filter = request.args.get('status', '')
    search        = request.args.get('search', '').strip()
    query  = ('SELECT a.*, u.full_name, u.username, u.email FROM applications a '
               'JOIN users u ON a.user_id=u.id WHERE 1=1')
    params = []
    if status_filter:
        query  += ' AND a.status=?'
        params.append(status_filter)
    if search:
        query  += ' AND (a.tracking_number LIKE ? OR u.full_name LIKE ? OR u.username LIKE ?)'
        params += [f'%{search}%', f'%{search}%', f'%{search}%']
    query += ' ORDER BY a.submitted_at DESC'
    apps = db.execute(query, params).fetchall()
    db.close()
    return render_template('officer/applications.html', applications=apps,
                           status_filter=status_filter, search=search)

@app.route('/officer/applications/<int:app_id>')
@officer_required
def officer_application_detail(app_id):
    db   = get_db()
    appl = db.execute('''
        SELECT a.*, u.full_name, u.username, u.email, u.public_key FROM applications a
        JOIN users u ON a.user_id=u.id WHERE a.id=?
    ''', (app_id,)).fetchone()
    if not appl:
        abort(404)
    docs      = db.execute('SELECT * FROM documents WHERE application_id=?', (app_id,)).fetchall()
    form_data = json.loads(appl['form_data'])
    db.close()
    return render_template('officer/application_detail.html', appl=appl, docs=docs, form_data=form_data)

@app.route('/officer/applications/<int:app_id>/action', methods=['POST'])
@officer_required
def officer_application_action(app_id):
    action = request.form.get('action')
    notes  = request.form.get('notes', '')

    if action == 'review':
        new_status, action_log = 'under_review', 'UNDER_REVIEW'
    elif action == 'approve':
        new_status, action_log = 'approved', 'APPROVE'
    elif action == 'reject':
        new_status, action_log = 'rejected', 'REJECT'
    elif action == 'request_docs':
        new_status, action_log = 'under_review', 'REQUEST_ADDITIONAL_DOCS'
    else:
        flash('Invalid action.', 'danger')
        return redirect(url_for('officer_application_detail', app_id=app_id))

    db = get_db()
    additional_flag = 1 if action == 'request_docs' else 0
    db.execute(
        'UPDATE applications SET status=?, admin_notes=?, updated_at=?, additional_docs_requested=? WHERE id=?',
        (new_status, notes, datetime.utcnow().isoformat(), additional_flag, app_id)
    )
    db.commit()
    appl = db.execute(
        'SELECT a.*, u.full_name FROM applications a JOIN users u ON a.user_id=u.id WHERE a.id=?',
        (app_id,)
    ).fetchone()
    log_action(db, session['user_id'], action_log,
               f'Officer action on {appl["tracking_number"]}: {new_status}', request.remote_addr)

    if new_status == 'approved':
        try:
            from utils.certificate_gen import generate_approval_certificate
            officer = db.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
            citizen = db.execute('SELECT * FROM users WHERE id=?', (appl['user_id'],)).fetchone()
            form_data = json.loads(appl['form_data'])
            citizenship_number = (form_data.get('citizenship_number') or
                                   form_data.get('pan_number') or '')
            cert_number, pdf_filename = generate_approval_certificate(
                dict(appl), dict(citizen), dict(officer), citizenship_number
            )
            db.execute(
                'INSERT OR REPLACE INTO approval_certificates '
                '(application_id, certificate_number, pdf_filename, officer_id, officer_name) '
                'VALUES (?,?,?,?,?)',
                (app_id, cert_number, pdf_filename, officer['id'], officer['full_name'])
            )
            db.commit()
            log_action(db, session['user_id'], 'CERT_GENERATED',
                       f'Approval certificate {cert_number} generated for {appl["tracking_number"]}',
                       request.remote_addr)
        except Exception as e:
            log_action(db, session['user_id'], 'CERT_GEN_ERROR',
                       f'Certificate generation failed: {e}', request.remote_addr)

    db.close()
    msg_map = {
        'review':       'Application marked as Under Review.',
        'approve':      'Application approved. Approval certificate generated.',
        'reject':       'Application rejected.',
        'request_docs': 'Additional documents requested from citizen.',
    }
    flash(msg_map.get(action, 'Action completed.'), 'success')
    return redirect(url_for('officer_application_detail', app_id=app_id))

@app.route('/officer/verify/<int:doc_id>', methods=['POST'])
@officer_required
def officer_verify_doc(doc_id):
    return _verify_doc_common(doc_id, 'OFFICER_VERIFY')

@app.route('/officer/download/<int:doc_id>')
@officer_required
def officer_download_doc(doc_id):
    return _download_doc(doc_id)

# ─── Admin routes ─────────────────────────────────────────────────────────────

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    db = get_db()
    total_citizens = db.execute("SELECT COUNT(*) as c FROM users WHERE role='citizen'").fetchone()['c']
    total_officers = db.execute("SELECT COUNT(*) as c FROM users WHERE role='officer'").fetchone()['c']
    total_apps     = db.execute("SELECT COUNT(*) as c FROM applications").fetchone()['c']
    pending        = db.execute("SELECT COUNT(*) as c FROM applications WHERE status='pending'").fetchone()['c']
    under_review   = db.execute("SELECT COUNT(*) as c FROM applications WHERE status='under_review'").fetchone()['c']
    approved       = db.execute("SELECT COUNT(*) as c FROM applications WHERE status='approved'").fetchone()['c']
    rejected       = db.execute("SELECT COUNT(*) as c FROM applications WHERE status='rejected'").fetchone()['c']
    verified_docs  = db.execute("SELECT COUNT(*) as c FROM documents WHERE is_verified=1").fetchone()['c']
    recent_apps    = db.execute('''
        SELECT a.*, u.full_name, u.username FROM applications a
        JOIN users u ON a.user_id=u.id ORDER BY a.submitted_at DESC LIMIT 10
    ''').fetchall()
    service_stats  = db.execute('SELECT service_type, COUNT(*) as cnt FROM applications GROUP BY service_type').fetchall()
    status_stats   = db.execute('SELECT status, COUNT(*) as cnt FROM applications GROUP BY status').fetchall()
    recent_logs    = db.execute('''
        SELECT al.*, u.username FROM audit_logs al
        LEFT JOIN users u ON al.user_id=u.id ORDER BY al.timestamp DESC LIMIT 10
    ''').fetchall()
    db.close()
    return render_template('admin/dashboard.html',
        stats={'citizens': total_citizens, 'officers': total_officers, 'total': total_apps,
               'pending': pending, 'under_review': under_review,
               'approved': approved, 'rejected': rejected, 'verified': verified_docs},
        recent_apps=recent_apps, service_stats=service_stats,
        status_stats=status_stats, recent_logs=recent_logs)

@app.route('/admin/applications')
@admin_required
def admin_applications():
    db  = get_db()
    status_filter = request.args.get('status', '')
    search        = request.args.get('search', '').strip()
    query  = ('SELECT a.*, u.full_name, u.username, u.email FROM applications a '
               'JOIN users u ON a.user_id=u.id WHERE 1=1')
    params = []
    if status_filter:
        query  += ' AND a.status=?'
        params.append(status_filter)
    if search:
        query  += ' AND (a.tracking_number LIKE ? OR u.full_name LIKE ? OR u.username LIKE ?)'
        params += [f'%{search}%', f'%{search}%', f'%{search}%']
    query += ' ORDER BY a.submitted_at DESC'
    apps = db.execute(query, params).fetchall()
    db.close()
    return render_template('admin/applications.html', applications=apps,
                           status_filter=status_filter, search=search)

@app.route('/admin/applications/<int:app_id>')
@admin_required
def admin_application_detail(app_id):
    db   = get_db()
    appl = db.execute('''
        SELECT a.*, u.full_name, u.username, u.email, u.public_key FROM applications a
        JOIN users u ON a.user_id=u.id WHERE a.id=?
    ''', (app_id,)).fetchone()
    if not appl:
        abort(404)
    docs      = db.execute('SELECT * FROM documents WHERE application_id=?', (app_id,)).fetchall()
    form_data = json.loads(appl['form_data'])
    db.close()
    return render_template('admin/application_detail.html', appl=appl, docs=docs, form_data=form_data)

@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    citizens = db.execute('''
        SELECT u.*, COUNT(a.id) as app_count FROM users u
        LEFT JOIN applications a ON u.id=a.user_id
        WHERE u.role='citizen' GROUP BY u.id ORDER BY u.created_at DESC
    ''').fetchall()
    officers = db.execute("SELECT * FROM users WHERE role='officer' ORDER BY created_at DESC").fetchall()
    db.close()
    return render_template('admin/users.html', citizens=citizens, officers=officers)

@app.route('/admin/users/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    cert = db.execute('SELECT * FROM certificates WHERE user_id=? ORDER BY issued_at DESC LIMIT 1', (user_id,)).fetchone()
    apps = db.execute('SELECT * FROM applications WHERE user_id=? ORDER BY submitted_at DESC', (user_id,)).fetchall()
    db.close()
    return render_template('admin/user_detail.html', user=user, cert=cert, applications=apps)

@app.route('/admin/officers/create', methods=['GET', 'POST'])
@admin_required
def admin_create_officer():
    if request.method == 'POST':
        username  = request.form.get('username', '').strip()
        email     = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        phone     = request.form.get('phone', '').strip()
        password  = request.form.get('password', '')
        if not all([username, email, full_name, phone, password]):
            flash('All fields are required.', 'danger')
            return render_template('admin/create_officer.html')
        db = get_db()
        if db.execute('SELECT id FROM users WHERE username=? OR email=?', (username, email)).fetchone():
            flash('Username or email already exists.', 'danger')
            db.close()
            return render_template('admin/create_officer.html')
        priv_store, pub, cert_pem, serial, exp = generate_user_keys_and_cert(full_name, email, username)
        pw_hash = generate_password_hash(password)
        cur = db.execute(
            'INSERT INTO users (username, email, password_hash, full_name, phone, role, public_key, private_key_encrypted) '
            'VALUES (?,?,?,?,?,?,?,?)',
            (username, email, pw_hash, full_name, phone, 'officer', pub, priv_store)
        )
        db.execute('INSERT INTO certificates (user_id, certificate_pem, serial_number, expires_at) VALUES (?,?,?,?)',
                   (cur.lastrowid, cert_pem, serial, exp))
        db.commit()
        log_action(db, session['user_id'], 'CREATE_OFFICER',
                   f'Admin created officer: {username}', request.remote_addr)
        db.close()
        flash(f'Government Officer account "{username}" created successfully.', 'success')
        return redirect(url_for('admin_users'))
    return render_template('admin/create_officer.html')

@app.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE id=? AND role != "admin"', (user_id,)).fetchone()
    if not user:
        abort(404)
    new_status = 0 if user['is_active'] else 1
    db.execute('UPDATE users SET is_active=? WHERE id=?', (new_status, user_id))
    db.commit()
    log_action(db, session['user_id'], 'ACTIVATE_USER' if new_status else 'DEACTIVATE_USER',
               f'User {user["username"]} active={new_status}', request.remote_addr)
    db.close()
    flash(f'User {user["username"]} has been {"activated" if new_status else "deactivated"}.', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def admin_reset_password(user_id):
    new_password = request.form.get('new_password', '')
    if len(new_password) < 8:
        flash('Password must be at least 8 characters.', 'danger')
        return redirect(url_for('admin_user_detail', user_id=user_id))
    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE id=? AND role != "admin"', (user_id,)).fetchone()
    if not user:
        abort(404)
    db.execute('UPDATE users SET password_hash=? WHERE id=?',
               (generate_password_hash(new_password), user_id))
    db.commit()
    log_action(db, session['user_id'], 'RESET_PASSWORD',
               f'Admin reset password for {user["username"]}', request.remote_addr)
    db.close()
    flash(f'Password for {user["username"]} has been reset.', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/users/<int:user_id>/revoke-cert', methods=['POST'])
@admin_required
def admin_revoke_cert(user_id):
    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE id=? AND role != "admin"', (user_id,)).fetchone()
    if not user:
        abort(404)
    reason = request.form.get('reason', 'Revoked by administrator').strip() or 'Revoked by administrator'
    cert   = db.execute('SELECT * FROM certificates WHERE user_id=? ORDER BY issued_at DESC LIMIT 1', (user_id,)).fetchone()
    if not cert:
        flash('No certificate found.', 'danger')
        db.close()
        return redirect(url_for('admin_user_detail', user_id=user_id))
    if not cert['is_valid']:
        flash('Certificate is already revoked.', 'warning')
        db.close()
        return redirect(url_for('admin_user_detail', user_id=user_id))
    db.execute(
        'UPDATE certificates SET is_valid=0, revoked_at=?, revoked_by=?, revocation_reason=? WHERE id=?',
        (datetime.utcnow().isoformat(), session['user_id'], reason, cert['id'])
    )
    db.commit()
    log_action(db, session['user_id'], 'REVOKE_CERT',
               f'Certificate revoked for {user["username"]}: {reason}', request.remote_addr)
    db.close()
    flash(f'Certificate for {user["username"]} has been revoked.', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/users/<int:user_id>/reissue-cert', methods=['POST'])
@admin_required
def admin_reissue_cert(user_id):
    db   = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not user or user['role'] == 'admin':
        abort(404)
    priv_store, pub_pem, cert_pem, serial, exp = \
        generate_user_keys_and_cert(user['full_name'], user['email'], user['username'])
    db.execute('UPDATE users SET public_key=?, private_key_encrypted=? WHERE id=?',
               (pub_pem, priv_store, user_id))
    db.execute('UPDATE certificates SET is_valid=0 WHERE user_id=?', (user_id,))
    db.execute(
    'INSERT INTO certificates (user_id, certificate_pem, serial_number, expires_at, is_valid) VALUES (?,?,?,?,?)',
    (user_id, cert_pem, serial, exp, 1)
)
    db.commit()
    log_action(db, session['user_id'], 'REISSUE_CERT',
               f'New certificate issued for {user["username"]}', request.remote_addr)
    db.close()
    flash(f'New certificate issued for {user["username"]}.', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/verify/<int:doc_id>', methods=['POST'])
@admin_required
def admin_verify_doc(doc_id):
    return _verify_doc_common(doc_id, 'ADMIN_VERIFY')

@app.route('/admin/download/<int:doc_id>')
@admin_required
def admin_download_doc(doc_id):
    return _download_doc(doc_id)

@app.route('/admin/audit-logs')
@admin_required
def admin_audit_logs():
    db   = get_db()
    logs = db.execute('''
        SELECT al.*, u.username FROM audit_logs al
        LEFT JOIN users u ON al.user_id=u.id ORDER BY al.timestamp DESC LIMIT 200
    ''').fetchall()
    db.close()
    return render_template('admin/audit_logs.html', logs=logs)

# ─── Shared helpers ───────────────────────────────────────────────────────────

def _verify_doc_common(doc_id: int, log_action_name: str):
    db  = get_db()
    row = db.execute(
        'SELECT d.*, u.public_key, u.private_key_encrypted, c.is_valid as cert_valid '
        'FROM documents d '
        'JOIN users u ON d.user_id=u.id '
        'LEFT JOIN certificates c ON c.user_id=u.id '
        'WHERE d.id=? ORDER BY c.issued_at DESC LIMIT 1',
        (doc_id,)
    ).fetchone()
    if not row:
        db.close()
        return jsonify({'result': 'error', 'message': 'Not found'})
    filepath = os.path.join(UPLOAD_FOLDER, row['filename'])
    try:
        with open(filepath, 'rb') as f:
            raw = f.read()
        if row['is_encrypted'] and row['encrypted_aes_key']:
            file_bytes = hybrid_decrypt(raw, row['encrypted_aes_key'], row['private_key_encrypted'])
        else:
            file_bytes = raw
        cert_valid = row['cert_valid'] if row['cert_valid'] is not None else 1
        vr = full_verify_document(file_bytes, row['file_hash'], row['signature'],
                                   row['public_key'], cert_valid)
        db.execute('UPDATE documents SET is_verified=1, verification_result=? WHERE id=?',
                   (vr.result_code, doc_id))
        db.commit()
        log_action(db, session['user_id'], log_action_name,
                   f'Document {doc_id} verified: {vr.result_code}', request.remote_addr)
        db.close()
        return jsonify({'result': vr.result_code, 'message': vr.message,
                        'hash': vr.details.get('current_hash', vr.details.get('hash', '')),
                        'stored_hash': row['file_hash']})
    except Exception as e:
        db.close()
        return jsonify({'result': 'error', 'message': str(e)})

def _download_doc(doc_id: int):
    db  = get_db()
    row = db.execute('SELECT * FROM documents WHERE id=?', (doc_id,)).fetchone()
    if not row:
        db.close()
        abort(404)
    filepath = os.path.join(UPLOAD_FOLDER, row['filename'])
    try:
        with open(filepath, 'rb') as f:
            raw = f.read()
        if row['is_encrypted'] and row['encrypted_aes_key']:
            owner = db.execute('SELECT private_key_encrypted FROM users WHERE id=?',
                                (row['user_id'],)).fetchone()
            db.close()
            plaintext = hybrid_decrypt(raw, row['encrypted_aes_key'], owner['private_key_encrypted'])
            import io as _io
            return send_file(
                _io.BytesIO(plaintext),
                as_attachment=True,
                download_name=row['original_filename'],
                mimetype=row['mime_type'] or 'application/octet-stream'
            )
        db.close()
        return send_from_directory(UPLOAD_FOLDER, row['filename'],
                                    as_attachment=True, download_name=row['original_filename'])
    except Exception:
        db.close()
        abort(500)

# ─── Shared API ───────────────────────────────────────────────────────────────

@app.route('/api/districts/<province>')
def get_districts(province):
    return jsonify(NEPAL_PROVINCES.get(province, []))

@app.errorhandler(403)
def forbidden(e):    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):    return render_template('errors/404.html'), 404

# ─── Seed defaults ────────────────────────────────────────────────────────────

def seed_defaults():
    db = get_db()
    if not db.execute("SELECT id FROM users WHERE role='admin'").fetchone():
        pw = generate_password_hash('Admin@2024#Secure')
        priv, pub, cert, serial, exp = generate_user_keys_and_cert('System Administrator', 'admin@gov.np', 'admin')
        cur = db.execute(
            'INSERT INTO users (username, email, password_hash, full_name, phone, role, public_key, private_key_encrypted) VALUES (?,?,?,?,?,?,?,?)',
            ('admin', 'admin@gov.np', pw, 'System Administrator', '9800000000', 'admin', pub, priv))
        db.execute('INSERT INTO certificates (user_id, certificate_pem, serial_number, expires_at) VALUES (?,?,?,?)',
                   (cur.lastrowid, cert, serial, exp))
        db.commit()
    if not db.execute("SELECT id FROM users WHERE role='officer'").fetchone():
        pw = generate_password_hash('Officer@2024#Secure')
        priv, pub, cert, serial, exp = generate_user_keys_and_cert('Government Officer', 'officer@gov.np', 'officer')
        cur = db.execute(
            'INSERT INTO users (username, email, password_hash, full_name, phone, role, public_key, private_key_encrypted) VALUES (?,?,?,?,?,?,?,?)',
            ('officer', 'officer@gov.np', pw, 'Government Officer', '9800000001', 'officer', pub, priv))
        db.execute('INSERT INTO certificates (user_id, certificate_pem, serial_number, expires_at) VALUES (?,?,?,?)',
                   (cur.lastrowid, cert, serial, exp))
        db.commit()
    db.close()

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('certificates', exist_ok=True)
    os.makedirs('generated_certificates', exist_ok=True)
    init_db()
    seed_defaults()
    app.run(debug=True, host='0.0.0.0', port=5000)
