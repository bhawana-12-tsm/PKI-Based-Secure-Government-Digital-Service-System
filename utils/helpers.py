import os
import uuid
import random
import string
from datetime import datetime
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_tracking_number(service_type):
    prefix_map = {
        'driving_license': 'DL',
        'business_registration': 'BR',
        'tax_filing': 'TF'
    }
    prefix = prefix_map.get(service_type, 'SV')
    date_str = datetime.utcnow().strftime('%Y%m%d')
    random_part = ''.join(random.choices(string.digits, k=6))
    return f"{prefix}-{date_str}-{random_part}"

def save_uploaded_file(file, user_id, app_id):
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    original_name = secure_filename(file.filename)
    ext = original_name.rsplit('.', 1)[1].lower() if '.' in original_name else 'bin'
    unique_name = f"{user_id}_{app_id}_{uuid.uuid4().hex}.{ext}"
    filepath = os.path.join(UPLOAD_FOLDER, unique_name)
    file_bytes = file.read()
    with open(filepath, 'wb') as f:
        f.write(file_bytes)
    return unique_name, file_bytes

NEPAL_PROVINCES = {
    'Koshi': ['Bhojpur', 'Dhankuta', 'Ilam', 'Jhapa', 'Khotang', 'Morang', 'Okhaldhunga', 'Panchthar', 'Sankhuwasabha', 'Solukhumbu', 'Sunsari', 'Taplejung', 'Terhathum', 'Udayapur'],
    'Madhesh': ['Bara', 'Dhanusha', 'Mahottari', 'Parsa', 'Rautahat', 'Saptari', 'Sarlahi', 'Siraha'],
    'Bagmati': ['Bhaktapur', 'Chitwan', 'Dhading', 'Dolakha', 'Kathmandu', 'Kavrepalanchok', 'Lalitpur', 'Makwanpur', 'Nuwakot', 'Rasuwa', 'Ramechhap', 'Sindhuli', 'Sindhupalchok'],
    'Gandaki': ['Baglung', 'Gorkha', 'Kaski', 'Lamjung', 'Manang', 'Mustang', 'Myagdi', 'Nawalpur', 'Parbat', 'Syangja', 'Tanahun'],
    'Lumbini': ['Arghakhanchi', 'Banke', 'Bardiya', 'Dang', 'Eastern Rukum', 'Gulmi', 'Kapilvastu', 'Nawalparasi', 'Palpa', 'Pyuthan', 'Rolpa', 'Rupandehi'],
    'Karnali': ['Dailekh', 'Dolpa', 'Humla', 'Jajarkot', 'Jumla', 'Kalikot', 'Mugu', 'Salyan', 'Surkhet', 'Western Rukum'],
    'Sudurpashchim': ['Achham', 'Baitadi', 'Bajhang', 'Bajura', 'Dadeldhura', 'Darchula', 'Doti', 'Kailali', 'Kanchanpur']
}

def log_action(db, user_id, action, details, ip_address):
    db.execute(
        'INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
        (user_id, action, details, ip_address)
    )
    db.commit()
