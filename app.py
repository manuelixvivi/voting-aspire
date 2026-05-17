import os
import csv
import io
import logging
import html
import re
import secrets
import hashlib
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, flash, abort, Response, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

base_dir = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__, 
    template_folder=os.path.join(base_dir, 'templates'), 
    static_folder=os.path.join(base_dir, 'static')
)

# ==================== CONFIGURATION ====================
# Secret key from environment
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Database: Supabase PostgreSQL (mencoba membaca key integrasi Vercel dulu, lalu fallback ke DATABASE_URL lokal)
db_url = os.environ.get('POSTGRES_URL_POSTGRES_URL') or os.environ.get('DATABASE_URL')

if db_url:
    # Fix for Supabase URL format (Vercel terkadang memberikan skema postgres://)
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
else:
    # Fallback to SQLite jika dijalankan di lokal tanpa DB eksternal
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sistem_kelas.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# CSRF Config
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

# Session config for serverless
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Silakan login untuk mengakses halaman ini.'
login_manager.login_message_category = 'warning'

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

# ==================== SECURITY HEADERS & MIDDLEWARE ====================
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Rate limiting helper
login_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

def check_rate_limit(identifier):
    now = datetime.now()
    if identifier in login_attempts:
        attempts, locked_until = login_attempts[identifier]
        if locked_until and now < locked_until:
            return False, locked_until
        if attempts >= MAX_ATTEMPTS:
            locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            login_attempts[identifier] = (attempts, locked_until)
            return False, locked_until
    return True, None

def record_failed_attempt(identifier):
    now = datetime.now()
    if identifier in login_attempts:
        attempts, _ = login_attempts[identifier]
        login_attempts[identifier] = (attempts + 1, None)
    else:
        login_attempts[identifier] = (1, None)

def clear_attempts(identifier):
    if identifier in login_attempts:
        del login_attempts[identifier]

# ==================== SANITIZATION ====================
def sanitize_input(text, max_length=2000):
    if text is None:
        return ''
    text = str(text).strip()
    if len(text) > max_length:
        text = text[:max_length]
    text = re.sub(r'<[^>]+>', '', text)
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'data:', '', text, flags=re.IGNORECASE)
    text = re.sub(r'vbscript:', '', text, flags=re.IGNORECASE)
    text = re.sub(r"on\w+\s*=\s*[\"']?[^\"'>]*[\"']?", '', text, flags=re.IGNORECASE)
    text = re.sub(r'expression\(', '', text, flags=re.IGNORECASE)
    text = html.escape(text)
    return text

def sanitize_filename(filename):
    if not filename:
        return 'unnamed'
    filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    return filename[:100]

def validate_nim(nim):
    if not nim:
        return False
    return bool(re.match(r'^[a-zA-Z0-9]{1,20}$', str(nim).strip()))

def validate_ipk(ipk_val):
    try:
        val = float(str(ipk_val).replace(',', '.'))
        return 0.0 <= val <= 4.0
    except (ValueError, TypeError):
        return False

# ==================== NAVIGATION HELPER ====================
class StudentNav:
    STEPS = [
        {'id': 'step1', 'name': 'Pilih Saran Divisi', 'url': 'pilihan_saran'},
        {'id': 'step2', 'name': 'Pilih Jabatan', 'url': 'pilih_jabatan'},
        {'id': 'step3', 'name': 'Pilih Koordinator', 'url': 'pilih_koordinator'},
    ]

    @classmethod
    def get_nav_items(cls, user, datasheet):
        if not user or not datasheet:
            return []
        status = user.get_completion_status()
        items = []
        for step in cls.STEPS:
            item = {
                'id': step['id'],
                'name': step['name'],
                'url': step['url'],
                'current': False,
                'accessible': False,
                'completed': False,
            }
            if step['id'] == 'step1':
                item['completed'] = bool(user.divisi_final)
                item['accessible'] = True
            elif step['id'] == 'step2':
                item['completed'] = bool(user.jabatan_final)
                item['accessible'] = bool(user.divisi_final)
            elif step['id'] == 'step3':
                expected_votes = len(datasheet.divisions) if datasheet else 0
                actual_votes = DivisionVote.query.filter_by(voter_nim=user.nim).count()
                item['completed'] = actual_votes >= expected_votes and expected_votes > 0
                item['accessible'] = bool(user.divisi_final)
            items.append(item)
        return items

# ==================== MODELS ====================
class DataSheet(db.Model):
    __tablename__ = 'datasheets'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=False)
    phase = db.Column(db.String(20), default='filling')
    start_time = db.Column(db.DateTime, nullable=True)
    deadline = db.Column(db.DateTime, nullable=True)
    announcement_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    students = db.relationship('User', backref='datasheet', lazy=True, cascade='all, delete-orphan')
    divisions = db.relationship('Division', backref='datasheet', lazy=True, cascade='all, delete-orphan')

    def is_schedule_active(self):
        now = datetime.now()
        if self.start_time and self.deadline:
            return self.start_time <= now <= self.deadline
        return self.is_active

    def is_expired(self):
        if self.deadline:
            return datetime.now() > self.deadline
        return False

    def get_time_remaining(self):
        if self.deadline:
            remaining = self.deadline - datetime.now()
            total_seconds = remaining.total_seconds()
            if total_seconds > 0:
                days = remaining.days
                hours, remainder = divmod(remaining.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                return {
                    'days': days,
                    'hours': hours,
                    'minutes': minutes,
                    'seconds': seconds,
                    'total_seconds': int(total_seconds)
                }
        return None

class Division(db.Model):
    __tablename__ = 'divisions'
    id = db.Column(db.Integer, primary_key=True)
    datasheet_id = db.Column(db.Integer, db.ForeignKey('datasheets.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)

class DivisionVote(db.Model):
    __tablename__ = 'division_votes'
    id = db.Column(db.Integer, primary_key=True)
    voter_nim = db.Column(db.String(20), db.ForeignKey('users.nim'), nullable=False)
    division_name = db.Column(db.String(100), nullable=False)
    recommended_koor_nim = db.Column(db.String(20), db.ForeignKey('users.nim'), nullable=True)

    __table_args__ = (db.UniqueConstraint('voter_nim', 'division_name', name='unique_div_vote'),)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    nim = db.Column(db.String(20), primary_key=True)
    nama = db.Column(db.String(100), nullable=False)
    ipk = db.Column(db.Float, nullable=False, default=0.0)
    password = db.Column(db.String(200), nullable=False)
    password_changed = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), nullable=False, default='mahasiswa')
    tawaran1 = db.Column(db.String(100))
    alasan_tawaran1 = db.Column(db.String(500))
    tawaran2 = db.Column(db.String(100))
    alasan_tawaran2 = db.Column(db.String(500))
    divisi_final = db.Column(db.String(100))
    jabatan_final = db.Column(db.String(50))
    alasan_penolakan = db.Column(db.String(500))
    alasan_final = db.Column(db.String(500))
    memilih_saran = db.Column(db.Boolean, default=False)
    datasheet_id = db.Column(db.Integer, db.ForeignKey('datasheets.id'), nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    login_count = db.Column(db.Integer, default=0)

    votes = db.relationship('DivisionVote', foreign_keys='DivisionVote.voter_nim', backref='voter', lazy=True, cascade='all, delete-orphan')

    def get_id(self):
        return self.nim

    def is_elite(self):
        return self.ipk > 3.5

    def get_completion_status(self):
        if not self.divisi_final:
            return 'step1'
        if self.memilih_saran and not self.jabatan_final:
            return 'step2'
        if self.jabatan_final or (not self.memilih_saran and self.divisi_final):
            expected_votes = 0
            ds = db.session.get(DataSheet, self.datasheet_id)
            if ds:
                expected_votes = len(ds.divisions)
            actual_votes = DivisionVote.query.filter_by(voter_nim=self.nim).count()
            if expected_votes > 0 and actual_votes < expected_votes:
                return 'step3'
            return 'complete'
        return 'step1'

class SystemConfig(db.Model):
    __tablename__ = 'system_config'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=False)

    @staticmethod
    def get_value(key, default=None):
        config = SystemConfig.query.filter_by(key=key).first()
        return config.value if config else default

    @staticmethod
    def set_value(key, value):
        config = SystemConfig.query.filter_by(key=key).first()
        if config:
            config.value = value
        else:
            config = SystemConfig(key=key, value=value)
            db.session.add(config)
        db.session.commit()

class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    event_type = db.Column(db.String(50), nullable=False)
    nim = db.Column(db.String(20))
    ip_address = db.Column(db.String(45))
    details = db.Column(db.String(500))

# ==================== DECORATORS ====================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            log_security_event('unauthorized_admin_access', current_user.nim if current_user.is_authenticated else None)
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def password_changed_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and not current_user.password_changed and current_user.role != 'admin':
            flash('Silakan ubah password Anda terlebih dahulu untuk keamanan akun.', 'warning')
            return redirect(url_for('change_password'))
        return f(*args, **kwargs)
    return decorated_function

def active_datasheet_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.role == 'mahasiswa':
            ds = db.session.get(DataSheet, current_user.datasheet_id)
            if not ds:
                flash('Anda belum terdaftar pada datasheet.', 'warning')
                return redirect(url_for('logout'))
            if not ds.is_active and not ds.is_schedule_active():
                flash('Datasheet Anda sedang tidak aktif.', 'warning')
                return redirect(url_for('logout'))
            if ds.is_expired():
                flash('Batas waktu pengisian telah berakhir.', 'danger')
                if request.endpoint not in ('student_portal', 'student_dashboard', 'tunggu_evaluasi', 'congrats_card'):
                    return redirect(url_for('student_portal'))
        return f(*args, **kwargs)
    return decorated_function

def filling_phase_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.role == 'mahasiswa':
            ds = db.session.get(DataSheet, current_user.datasheet_id)
            if not ds or ds.phase != 'filling':
                flash('Fase pengisian telah ditutup.', 'warning')
                return redirect(url_for('student_portal'))
        return f(*args, **kwargs)
    return decorated_function

def log_security_event(event_type, nim=None, details=None):
    try:
        log = SecurityLog(
            event_type=event_type,
            nim=nim,
            ip_address=request.remote_addr,
            details=details[:500] if details else None
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()

# ==================== ROUTES ====================
@login_manager.user_loader
def load_user(nim):
    return db.session.get(User, nim)

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            nama_ketua = SystemConfig.get_value('nama_ketua', 'admin')
            return redirect(url_for('admin_dashboard', nama=nama_ketua))
        if not current_user.password_changed:
            return redirect(url_for('change_password'))
        return redirect(url_for('student_portal'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nim = sanitize_input(request.form.get('nim', '')).strip()
        password = request.form.get('password', '')

        if not nim or not password:
            flash('NIM dan Password wajib diisi.', 'danger')
            return redirect(url_for('login'))

        if not validate_nim(nim):
            flash('Format NIM tidak valid.', 'danger')
            return redirect(url_for('login'))

        identifier = f"{nim}_{request.remote_addr}"
        allowed, locked_until = check_rate_limit(identifier)
        if not allowed:
            flash(f'Terlalu banyak percobaan login. Coba lagi setelah {locked_until.strftime("%H:%M")}.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(nim=nim).first()

        if user and check_password_hash(user.password, password):
            clear_attempts(identifier)

            if user.role == 'mahasiswa':
                if not user.datasheet_id:
                    flash('Anda belum terdaftar pada datasheet manapun. Hubungi admin.', 'danger')
                    return redirect(url_for('login'))
                ds = db.session.get(DataSheet, user.datasheet_id)
                if not ds:
                    flash('Datasheet tidak ditemukan. Hubungi admin.', 'danger')
                    return redirect(url_for('login'))

            user.last_login = datetime.now()
            user.login_count += 1
            db.session.commit()

            login_user(user, remember=False)
            session.permanent = True
            log_security_event('login_success', nim)
            flash(f'Selamat datang, {sanitize_input(user.nama)}.', 'success')

            if user.role == 'admin':
                nama_ketua = SystemConfig.get_value('nama_ketua', 'admin')
                nama_wakil = SystemConfig.get_value('nama_wakil', 'wakil')
                nim_ketua = SystemConfig.get_value('nim_ketua', 'ketua')
                nim_wakil = SystemConfig.get_value('nim_wakil', 'wakil')

                if user.nim == nim_ketua:
                    return redirect(url_for('admin_dashboard', nama=nama_ketua))
                elif user.nim == nim_wakil:
                    return redirect(url_for('admin_dashboard', nama=nama_wakil))
                else:
                    return redirect(url_for('admin_dashboard', nama=nama_ketua))

            if not user.password_changed:
                return redirect(url_for('change_password'))
            return redirect(url_for('student_portal'))
        else:
            record_failed_attempt(identifier)
            log_security_event('login_failed', nim, 'Invalid credentials')
            flash('NIM atau Password salah.', 'danger')

    return render_template('login.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_pass = request.form.get('old_password', '')
        new_pass = request.form.get('new_password', '')
        confirm_pass = request.form.get('confirm_password', '')

        if not old_pass or not new_pass or not confirm_pass:
            flash('Semua field wajib diisi.', 'danger')
            return redirect(url_for('change_password'))

        if not check_password_hash(current_user.password, old_pass):
            flash('Password lama tidak sesuai.', 'danger')
            return redirect(url_for('change_password'))

        if len(new_pass) < 8:
            flash('Password baru minimal 8 karakter.', 'danger')
            return redirect(url_for('change_password'))

        if not re.search(r'[A-Za-z]', new_pass) or not re.search(r'[0-9]', new_pass):
            flash('Password harus mengandung huruf dan angka.', 'danger')
            return redirect(url_for('change_password'))

        if new_pass.lower() in ['password', '12345678', 'qwerty123']:
            flash('Password terlalu umum. Gunakan password yang lebih kuat.', 'danger')
            return redirect(url_for('change_password'))

        if new_pass != confirm_pass:
            flash('Konfirmasi password tidak cocok.', 'danger')
            return redirect(url_for('change_password'))

        current_user.password = generate_password_hash(new_pass)
        current_user.password_changed = True
        db.session.commit()
        log_security_event('password_changed', current_user.nim)
        flash('Password berhasil diubah. Selamat menggunakan sistem.', 'success')
        return redirect(url_for('index'))

    return render_template('change_password.html')

@app.route('/logout')
@login_required
def logout():
    log_security_event('logout', current_user.nim)
    logout_user()
    flash('Anda telah keluar dari sistem.', 'info')
    return redirect(url_for('login'))

# ==================== STUDENT PORTAL ====================
@app.route('/portal')
@login_required
@password_changed_required
def student_portal():
    if current_user.role != 'mahasiswa':
        abort(403)
    ds = db.session.get(DataSheet, current_user.datasheet_id)
    if not ds:
        abort(404)

    if ds.phase == 'filling':
        return redirect(url_for('student_dashboard'))
    elif ds.phase == 'evaluation':
        return redirect(url_for('tunggu_evaluasi'))
    elif ds.phase == 'announcement':
        return redirect(url_for('congrats_card'))
    else:
        abort(400)

@app.route('/student-dashboard')
@login_required
@password_changed_required
@active_datasheet_required
def student_dashboard():
    if current_user.role != 'mahasiswa':
        abort(403)
    ds = db.session.get(DataSheet, current_user.datasheet_id)
    if not ds or ds.phase != 'filling':
        return redirect(url_for('student_portal'))

    status = current_user.get_completion_status()
    time_remaining = ds.get_time_remaining()
    nav_items = StudentNav.get_nav_items(current_user, ds)

    return render_template('student_dashboard.html',
                           datasheet=ds,
                           status=status,
                           time_remaining=time_remaining,
                           nav_items=nav_items)

@app.route('/api/time-remaining/<int:ds_id>')
@login_required
def api_time_remaining(ds_id):
    ds = db.session.get(DataSheet, ds_id)
    if not ds:
        return jsonify({'error': 'Not found'}), 404
    if current_user.role == 'mahasiswa' and current_user.datasheet_id != ds_id:
        return jsonify({'error': 'Forbidden'}), 403

    remaining = ds.get_time_remaining()
    is_expired = ds.is_expired()

    return jsonify({
        'remaining': remaining,
        'is_expired': is_expired,
        'deadline': ds.deadline.isoformat() if ds.deadline else None
    })

@app.route('/pilihan-saran')
@login_required
@password_changed_required
@active_datasheet_required
@filling_phase_required
def pilihan_saran():
    if current_user.role != 'mahasiswa':
        abort(403)
    ds = db.session.get(DataSheet, current_user.datasheet_id)
    if not ds:
        abort(404)

    time_remaining = ds.get_time_remaining()
    nav_items = StudentNav.get_nav_items(current_user, ds)

    return render_template('student_pilih_saran.html',
                           datasheet=ds,
                           time_remaining=time_remaining,
                           nav_items=nav_items)

@app.route('/submit-saran', methods=['POST'])
@login_required
@password_changed_required
@active_datasheet_required
@filling_phase_required
def submit_saran():
    if current_user.role != 'mahasiswa':
        abort(403)
    ds = db.session.get(DataSheet, current_user.datasheet_id)
    if not ds:
        abort(404)

    pilihan = request.form.get('pilihan', '').strip()

    if pilihan == 'terima':
        tawaran = sanitize_input(request.form.get('tawaran_diterima', '')).strip()
        if tawaran not in [current_user.tawaran1, current_user.tawaran2]:
            flash('Tawaran tidak valid.', 'danger')
            return redirect(url_for('pilihan_saran'))

        current_user.divisi_final = tawaran
        current_user.memilih_saran = True
        current_user.alasan_penolakan = None
        db.session.commit()
        log_security_event('saran_accepted', current_user.nim, f'Divisi: {tawaran}')
        return redirect(url_for('pilih_jabatan'))

    elif pilihan == 'tolak':
        divisi = request.form.get('divisi_custom', '').strip()
        alasan = sanitize_input(request.form.get('alasan_penolakan', '')).strip()

        valid_divisions = [d.name for d in ds.divisions]
        if divisi not in valid_divisions:
            flash(f'Divisi "{divisi}" tidak valid.', 'danger')
            return redirect(url_for('pilihan_saran'))

        if not alasan or len(alasan) < 10:
            flash('Alasan penolakan wajib diisi minimal 10 karakter.', 'danger')
            return redirect(url_for('pilihan_saran'))

        current_user.divisi_final = divisi
        current_user.alasan_penolakan = alasan
        current_user.memilih_saran = False
        current_user.jabatan_final = 'Anggota'
        db.session.commit()
        log_security_event('saran_rejected', current_user.nim, f'Divisi: {divisi}')
        return redirect(url_for('pilih_koordinator'))

    flash('Pilihan tidak valid.', 'danger')
    return redirect(url_for('pilihan_saran'))

@app.route('/pilih-jabatan')
@login_required
@password_changed_required
@active_datasheet_required
@filling_phase_required
def pilih_jabatan():
    if current_user.role != 'mahasiswa':
        abort(403)
    ds = db.session.get(DataSheet, current_user.datasheet_id)
    if not ds:
        abort(404)
    if not current_user.memilih_saran or not current_user.divisi_final:
        flash('Anda tidak memiliki akses ke halaman ini.', 'warning')
        return redirect(url_for('pilihan_saran'))

    time_remaining = ds.get_time_remaining()
    nav_items = StudentNav.get_nav_items(current_user, ds)

    return render_template('student_pilih_jabatan.html',
                           datasheet=ds,
                           time_remaining=time_remaining,
                           nav_items=nav_items)

@app.route('/submit-jabatan', methods=['POST'])
@login_required
@password_changed_required
@active_datasheet_required
@filling_phase_required
def submit_jabatan():
    if current_user.role != 'mahasiswa':
        abort(403)
    ds = db.session.get(DataSheet, current_user.datasheet_id)
    if not ds:
        abort(404)

    jabatan = sanitize_input(request.form.get('jabatan', '')).strip()

    if jabatan == 'Koordinator' and current_user.ipk <= 3.5:
        log_security_event('ipk_bypass_attempt', current_user.nim, f'IPK: {current_user.ipk}')
        flash('ERROR: IPK anda tidak memenuhi syarat koordinator (Min. 3.51)', 'danger')
        return redirect(url_for('pilih_jabatan'))

    if jabatan not in ['Koordinator', 'Anggota']:
        flash('Jabatan tidak valid.', 'danger')
        return redirect(url_for('pilih_jabatan'))

    current_user.jabatan_final = jabatan
    db.session.commit()
    log_security_event('jabatan_selected', current_user.nim, f'Jabatan: {jabatan}')
    return redirect(url_for('pilih_koordinator'))

@app.route('/pilih-koordinator')
@login_required
@password_changed_required
@active_datasheet_required
@filling_phase_required
def pilih_koordinator():
    if current_user.role != 'mahasiswa':
        abort(403)
    ds = db.session.get(DataSheet, current_user.datasheet_id)
    if not ds:
        abort(404)
    if not current_user.divisi_final:
        flash('Silakan pilih divisi terlebih dahulu.', 'warning')
        return redirect(url_for('pilihan_saran'))

    divisions = [d.name for d in ds.divisions]
    elite_students = User.query.filter(
        User.datasheet_id == ds.id,
        User.role == 'mahasiswa',
        User.ipk > 3.5
    ).all()

    existing_votes = {v.division_name: v.recommended_koor_nim for v in current_user.votes}
    time_remaining = ds.get_time_remaining()
    nav_items = StudentNav.get_nav_items(current_user, ds)

    return render_template('student_pilih_koordinator.html',
                           datasheet=ds,
                           divisions=divisions,
                           elite_students=elite_students,
                           existing_votes=existing_votes,
                           time_remaining=time_remaining,
                           nav_items=nav_items)

@app.route('/submit-koordinator', methods=['POST'])
@login_required
@password_changed_required
@active_datasheet_required
@filling_phase_required
def submit_koordinator():
    if current_user.role != 'mahasiswa':
        abort(403)
    ds = db.session.get(DataSheet, current_user.datasheet_id)
    if not ds:
        abort(404)

    divisions = [d.name for d in ds.divisions]
    vote_count = 0

    try:
        for div_name in divisions:
            koor_nim = sanitize_input(request.form.get(f'koor_{div_name}', '')).strip()

            if koor_nim:
                nominee = db.session.get(User, koor_nim)
                if not nominee or nominee.ipk <= 3.5:
                    flash(f'Kandidat koordinator untuk {div_name} tidak valid.', 'danger')
                    return redirect(url_for('pilih_koordinator'))

                existing = DivisionVote.query.filter_by(voter_nim=current_user.nim, division_name=div_name).first()
                if existing:
                    existing.recommended_koor_nim = koor_nim
                else:
                    vote = DivisionVote(voter_nim=current_user.nim, division_name=div_name, recommended_koor_nim=koor_nim)
                    db.session.add(vote)
                vote_count += 1
            else:
                existing = DivisionVote.query.filter_by(voter_nim=current_user.nim, division_name=div_name).first()
                if existing:
                    db.session.delete(existing)

        db.session.commit()
        log_security_event('koordinator_voted', current_user.nim, f'Votes: {vote_count}')
        flash('Semua pilihan berhasil disimpan.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error saving votes: {e}')
        flash('Terjadi kesalahan saat menyimpan voting.', 'danger')

    return redirect(url_for('pilih_koordinator'))

@app.route('/go-to-step/<step_id>')
@login_required
@password_changed_required
@active_datasheet_required
@filling_phase_required
def go_to_step(step_id):
    if current_user.role != 'mahasiswa':
        abort(403)

    ds = db.session.get(DataSheet, current_user.datasheet_id)
    nav_items = StudentNav.get_nav_items(current_user, ds)

    target = None
    for item in nav_items:
        if item['id'] == step_id:
            target = item
            break

    if not target:
        flash('Step tidak ditemukan.', 'danger')
        return redirect(url_for('student_dashboard'))

    if not target['accessible']:
        flash('Anda belum bisa mengakses step tersebut. Selesaikan step sebelumnya.', 'warning')
        return redirect(url_for('student_dashboard'))

    return redirect(url_for(target['url']))

@app.route('/tunggu-evaluasi')
@login_required
@password_changed_required
def tunggu_evaluasi():
    if current_user.role != 'mahasiswa':
        abort(403)
    ds = db.session.get(DataSheet, current_user.datasheet_id)
    if not ds or ds.phase != 'evaluation':
        return redirect(url_for('student_portal'))
    return render_template('student_wait.html', datasheet=ds)

@app.route('/congrats_card')
@login_required
@password_changed_required
def congrats_card():
    if current_user.role != 'mahasiswa':
        abort(403)
    ds = db.session.get(DataSheet, current_user.datasheet_id)
    if not ds or ds.phase != 'announcement':
        return redirect(url_for('student_portal'))
    if not current_user.divisi_final:
        flash('Anda belum memiliki pengumuman jabatan.', 'warning')
        return redirect(url_for('student_portal'))
    return render_template('congrats_card.html', datasheet=ds)

# ==================== ADMIN DASHBOARD ====================
@app.route('/papan_kendali/<nama>')
@login_required
@admin_required
def admin_dashboard(nama):
    nama_ketua = SystemConfig.get_value('nama_ketua', '')
    nama_wakil = SystemConfig.get_value('nama_wakil', '')
    if nama not in [nama_ketua, nama_wakil]:
        abort(404)

    datasheets = DataSheet.query.order_by(DataSheet.created_at.desc()).all()
    recent_logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(50).all()

    return render_template('admin_dashboard.html',
                           nama=nama,
                           datasheets=datasheets,
                           recent_logs=recent_logs)

@app.route('/admin/datasheet/<int:ds_id>')
@login_required
@admin_required
def datasheet_detail(ds_id):
    ds = db.session.get(DataSheet, ds_id) or abort(404)
    tab = sanitize_input(request.args.get('tab', 'overview'), max_length=50)
    valid_tabs = ['overview', 'students', 'votes', 'rejections', 'stats', 'security']
    if tab not in valid_tabs:
        tab = 'overview'

    students = [s for s in ds.students if s.role == 'mahasiswa']
    divisions = [d.name for d in ds.divisions]

    total = len(students)
    sudah = sum(1 for s in students if s.get_completion_status() == 'complete')
    belum = total - sudah

    div_stats = {}
    for div in ds.divisions:
        count = sum(1 for s in students if s.divisi_final == div.name)
        pct = round((count / total * 100), 1) if total > 0 else 0
        koor_candidates = [s for s in students if s.ipk > 3.5 and (s.divisi_final == div.name or s.tawaran1 == div.name or s.tawaran2 == div.name)]

        votes = DivisionVote.query.filter_by(division_name=div.name).all()
        vote_count = {}
        for v in votes:
            if v.recommended_koor_nim:
                vote_count[v.recommended_koor_nim] = vote_count.get(v.recommended_koor_nim, 0) + 1

        top_koor = []
        for nim_v, count_v in sorted(vote_count.items(), key=lambda x: x[1], reverse=True)[:3]:
            user = db.session.get(User, nim_v)
            if user:
                top_koor.append({'nama': user.nama, 'nim': nim_v, 'votes': count_v, 'ipk': user.ipk})

        div_stats[div.name] = {
            'count': count,
            'percentage': pct,
            'candidates': koor_candidates,
            'top_koor': top_koor
        }

    rejections = [s for s in students if s.alasan_penolakan]

    all_votes = []
    for s in students:
        votes = DivisionVote.query.filter_by(voter_nim=s.nim).all()
        vote_detail = {'nama': s.nama, 'nim': s.nim, 'votes': []}
        for v in votes:
            koor = db.session.get(User, v.recommended_koor_nim) if v.recommended_koor_nim else None
            vote_detail['votes'].append({
                'divisi': v.division_name,
                'koor': koor.nama if koor else '-'
            })
        all_votes.append(vote_detail)

    ds_logs = SecurityLog.query.filter(
        SecurityLog.nim.in_([s.nim for s in students])
    ).order_by(SecurityLog.timestamp.desc()).limit(100).all()

    return render_template('admin_datasheet_detail.html',
                           datasheet=ds,
                           tab=tab,
                           students=students,
                           divisions=divisions,
                           total=total,
                           sudah=sudah,
                           belum=belum,
                           div_stats=div_stats,
                           rejections=rejections,
                           all_votes=all_votes,
                           ds_logs=ds_logs)

@app.route('/admin/datasheet/create', methods=['POST'])
@login_required
@admin_required
def create_datasheet():
    name = sanitize_input(request.form.get('name', '')).strip()
    description = sanitize_input(request.form.get('description', '')).strip()
    start_str = sanitize_input(request.form.get('start_time', '')).strip()
    deadline_str = sanitize_input(request.form.get('deadline', '')).strip()
    divisions_raw = sanitize_input(request.form.get('divisions', '')).strip()

    if not name:
        flash('Nama datasheet wajib diisi.', 'danger')
        return redirect(request.referrer or url_for('index'))

    if len(name) > 100:
        flash('Nama datasheet maksimal 100 karakter.', 'danger')
        return redirect(request.referrer or url_for('index'))

    start_time = None
    if start_str:
        try:
            start_time = datetime.fromisoformat(start_str)
        except ValueError:
            flash('Format waktu mulai tidak valid.', 'danger')
            return redirect(request.referrer or url_for('index'))

    deadline = None
    if deadline_str:
        try:
            deadline = datetime.fromisoformat(deadline_str)
            if start_time and deadline <= start_time:
                flash('Deadline harus setelah waktu mulai.', 'danger')
                return redirect(request.referrer or url_for('index'))
        except ValueError:
            flash('Format deadline tidak valid.', 'danger')
            return redirect(request.referrer or url_for('index'))

    try:
        ds = DataSheet(name=name, description=description, start_time=start_time, deadline=deadline)
        db.session.add(ds)
        db.session.flush()

        div_list = []
        if divisions_raw:
            div_list = [d.strip() for d in divisions_raw.split(',') if d.strip()]
        for div_name in div_list:
            if len(div_name) > 100:
                div_name = div_name[:100]
            db.session.add(Division(datasheet_id=ds.id, name=div_name))

        db.session.commit()
        log_security_event('datasheet_created', current_user.nim, f'ID: {ds.id}, Name: {name}')
        flash(f'Datasheet "{name}" berhasil dibuat dengan {len(div_list)} divisi.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error creating datasheet: {e}')
        flash('Terjadi kesalahan saat membuat datasheet.', 'danger')

    return redirect(request.referrer or url_for('index'))

@app.route('/admin/datasheet/<int:ds_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_datasheet(ds_id):
    ds = db.session.get(DataSheet, ds_id) or abort(404)
    try:
        db.session.delete(ds)
        db.session.commit()
        log_security_event('datasheet_deleted', current_user.nim, f'ID: {ds_id}')
        flash(f'Datasheet "{ds.name}" berhasil dihapus.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting datasheet: {e}')
        flash('Terjadi kesalahan saat menghapus datasheet.', 'danger')
    return redirect(request.referrer or url_for('index'))

@app.route('/admin/datasheet/<int:ds_id>/activate', methods=['POST'])
@login_required
@admin_required
def activate_datasheet(ds_id):
    ds = db.session.get(DataSheet, ds_id) or abort(404)
    try:
        for other in DataSheet.query.filter(DataSheet.id != ds_id).all():
            if other.is_active:
                other.is_active = False
        ds.is_active = not ds.is_active
        db.session.commit()
        status = 'diaktifkan' if ds.is_active else 'dinonaktifkan'
        log_security_event('datasheet_toggled', current_user.nim, f'ID: {ds_id}, Status: {status}')
        flash(f'Datasheet "{ds.name}" telah {status}.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan.', 'danger')
    return redirect(request.referrer or url_for('index'))

@app.route('/admin/datasheet/<int:ds_id>/phase', methods=['POST'])
@login_required
@admin_required
def set_phase(ds_id):
    ds = db.session.get(DataSheet, ds_id) or abort(404)
    phase = sanitize_input(request.form.get('phase', ''), max_length=20).strip()

    valid_phases = ['filling', 'evaluation', 'announcement']
    if phase not in valid_phases:
        flash('Fase tidak valid.', 'danger')
        return redirect(url_for('datasheet_detail', ds_id=ds_id))

    try:
        ds.phase = phase
        db.session.commit()
        log_security_event('phase_changed', current_user.nim, f'ID: {ds_id}, Phase: {phase}')
        flash(f'Fase "{ds.name}" diubah ke {phase}.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan saat mengubah fase.', 'danger')

    return redirect(url_for('datasheet_detail', ds_id=ds_id))

@app.route('/admin/datasheet/<int:ds_id>/announcement-message', methods=['POST'])
@login_required
@admin_required
def save_announcement_message(ds_id):
    ds = db.session.get(DataSheet, ds_id) or abort(404)
    message = request.form.get('announcement_message', '').strip()

    try:
        ds.announcement_message = message if message else None
        db.session.commit()
        log_security_event('announcement_message_updated', current_user.nim, f'Datasheet: {ds_id}')
        flash('Pesan pengumuman berhasil disimpan.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan saat menyimpan pesan.', 'danger')

    return redirect(request.referrer or url_for('datasheet_detail', ds_id=ds_id))

@app.route('/admin/datasheet/<int:ds_id>/upload', methods=['POST'])
@login_required
@admin_required
def upload_csv(ds_id):
    ds = db.session.get(DataSheet, ds_id) or abort(404)

    if 'csv_file' not in request.files:
        flash('Tidak ada file yang dipilih.', 'danger')
        return redirect(request.referrer or url_for('index'))

    file = request.files['csv_file']
    if file.filename == '' or not file.filename.endswith('.csv'):
        flash('Format file harus CSV.', 'danger')
        return redirect(request.referrer or url_for('index'))

    valid_divisions = {d.name for d in ds.divisions}

    try:
        stream = io.StringIO(file.stream.read().decode("UTF-8"), newline=None)
        csv_reader = csv.DictReader(stream)

        count = 0
        invalid_divisions = set()
        rows_to_process = []

        for row in csv_reader:
            nim = sanitize_input(row.get('nim', '')).strip()
            if not nim:
                continue

            if not validate_nim(nim):
                flash(f'Format NIM tidak valid: {nim}', 'danger')
                return redirect(request.referrer or url_for('index'))

            tawaran1 = sanitize_input(row.get('tawaran1', ''))
            tawaran2 = sanitize_input(row.get('tawaran2', ''))

            if tawaran1 and tawaran1 not in valid_divisions:
                invalid_divisions.add(tawaran1)
            if tawaran2 and tawaran2 not in valid_divisions:
                invalid_divisions.add(tawaran2)

            ipk_str = row.get('ipk', '0').replace(',', '.')
            if not validate_ipk(ipk_str):
                flash(f'IPK tidak valid untuk NIM {nim}: {ipk_str}', 'danger')
                return redirect(request.referrer or url_for('index'))

            rows_to_process.append({
                'nim': nim,
                'nama': sanitize_input(row.get('nama', 'Tanpa Nama')),
                'ipk': float(ipk_str),
                'password': row.get('password', 'password123'),
                'tawaran1': tawaran1,
                'alasan_tawaran1': sanitize_input(row.get('alasan_tawaran1', '')),
                'tawaran2': tawaran2,
                'alasan_tawaran2': sanitize_input(row.get('alasan_tawaran2', ''))
            })

        if invalid_divisions:
            flash(f'Upload DITOLAK. Divisi tidak valid: {", ".join(invalid_divisions)}.', 'danger')
            return redirect(request.referrer or url_for('index'))

        for row_data in rows_to_process:
            existing = db.session.get(User, row_data['nim'])
            if not existing:
                user = User(
                    nim=row_data['nim'],
                    nama=row_data['nama'],
                    ipk=row_data['ipk'],
                    password=generate_password_hash(sanitize_input(row_data['password'])),
                    role='mahasiswa',
                    tawaran1=row_data['tawaran1'],
                    alasan_tawaran1=row_data['alasan_tawaran1'],
                    tawaran2=row_data['tawaran2'],
                    alasan_tawaran2=row_data['alasan_tawaran2'],
                    datasheet_id=ds.id
                )
                db.session.add(user)
                count += 1
            else:
                existing.datasheet_id = ds.id
                existing.tawaran1 = row_data['tawaran1']
                existing.alasan_tawaran1 = row_data['alasan_tawaran1']
                existing.tawaran2 = row_data['tawaran2']
                existing.alasan_tawaran2 = row_data['alasan_tawaran2']

        db.session.commit()
        log_security_event('csv_uploaded', current_user.nim, f'Datasheet: {ds_id}, Count: {count}')
        flash(f'Berhasil mengimpor {count} data ke "{ds.name}".', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'CSV upload error: {e}')
        flash(f'Error saat mengimpor: {str(e)}', 'danger')

    return redirect(request.referrer or url_for('index'))

@app.route('/admin/datasheet/<int:ds_id>/template')
@login_required
@admin_required
def download_template(ds_id):
    ds = db.session.get(DataSheet, ds_id) or abort(404)
    divisions = [d.name for d in ds.divisions]

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(['nim', 'nama', 'ipk', 'password', 'tawaran1', 'alasan_tawaran1', 'tawaran2', 'alasan_tawaran2'])
    writer.writerow(['CONTOH', 'Nama Lengkap', '3.50', 'pass123', divisions[0] if divisions else 'Divisi A', 'Alasan memilih', divisions[1] if len(divisions) > 1 else 'Divisi B', 'Alasan memilih'])
    writer.writerow(['20210001', 'Andi Wijaya', '3.85', 'pass123', divisions[0] if divisions else 'Divisi A', 'Prestasi akademik baik', divisions[1] if len(divisions) > 1 else 'Divisi B', 'Aktif di organisasi'])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment;filename=template_{sanitize_filename(ds.name)}.csv"}
    )

@app.route('/admin/datasheet/<int:ds_id>/reset-password/<nim>', methods=['POST'])
@login_required
@admin_required
def reset_password(ds_id, nim):
    ds = db.session.get(DataSheet, ds_id) or abort(404)
    user = db.session.get(User, nim) or abort(404)

    new_pass = request.form.get('new_password', '').strip()
    if len(new_pass) < 8:
        flash('Password minimal 8 karakter.', 'danger')
        return redirect(request.referrer or url_for('datasheet_detail', ds_id=ds_id, tab='students'))

    if not re.search(r'[A-Za-z]', new_pass) or not re.search(r'[0-9]', new_pass):
        flash('Password harus mengandung huruf dan angka.', 'danger')
        return redirect(request.referrer or url_for('datasheet_detail', ds_id=ds_id, tab='students'))

    try:
        user.password = generate_password_hash(new_pass)
        user.password_changed = False
        db.session.commit()
        log_security_event('password_reset', current_user.nim, f'Target: {nim}')
        flash(f'Password {user.nama} berhasil direset. User harus login ulang dan mengubah password.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Terjadi kesalahan.', 'danger')

    return redirect(request.referrer or url_for('datasheet_detail', ds_id=ds_id, tab='students'))

@app.route('/admin/datasheet/<int:ds_id>/evaluate')
@login_required
@admin_required
def evaluate_datasheet(ds_id):
    ds = db.session.get(DataSheet, ds_id) or abort(404)
    students = User.query.filter_by(datasheet_id=ds.id, role='mahasiswa').all()
    divisions = [d.name for d in ds.divisions]
    return render_template('admin_evaluation.html',
                           datasheet=ds,
                           students=students,
                           divisions=divisions)

@app.route('/admin/datasheet/<int:ds_id>/evaluate/save', methods=['POST'])
@login_required
@admin_required
def save_evaluation(ds_id):
    ds = db.session.get(DataSheet, ds_id) or abort(404)
    students = User.query.filter_by(datasheet_id=ds.id, role='mahasiswa').all()
    valid_divisions = [d.name for d in ds.divisions]

    try:
        for student in students:
            pilihan = sanitize_input(request.form.get(f'jabatan_{student.nim}', '')).strip()
            divisi = sanitize_input(request.form.get(f'divisi_{student.nim}', '')).strip()
            alasan_final = sanitize_input(request.form.get(f'alasan_final_{student.nim}', '')).strip()

            if pilihan and pilihan == 'Koordinator' and student.ipk <= 3.5:
                flash(f'ERROR: {student.nama} tidak memenuhi syarat Koordinator.', 'danger')
                continue

            if divisi and divisi not in valid_divisions:
                flash(f'Divisi "{divisi}" tidak ada di master list untuk {student.nama}.', 'warning')
                continue

            if pilihan:
                student.jabatan_final = pilihan
            if divisi:
                student.divisi_final = divisi
            if alasan_final:
                student.alasan_final = alasan_final

        db.session.commit()
        log_security_event('evaluation_saved', current_user.nim, f'Datasheet: {ds_id}')
        flash('Evaluasi berhasil disimpan.', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Evaluation save error: {e}')
        flash('Terjadi kesalahan saat menyimpan evaluasi.', 'danger')

    return redirect(url_for('evaluate_datasheet', ds_id=ds_id))

@app.route('/admin/security-logs')
@login_required
@admin_required
def security_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    logs_query = SecurityLog.query.order_by(SecurityLog.timestamp.desc())
    logs = logs_query.limit(per_page).offset((page - 1) * per_page).all()
    total = logs_query.count()
    return render_template('admin_security_logs.html', logs=logs, page=page, total=total, per_page=per_page)

# ==================== ERROR HANDLERS ====================
@app.errorhandler(400)
def handle_400(e):
    if 'CSRF' in str(e) or 'csrf' in str(e).lower():
        log_security_event('csrf_error', None, str(e))
        return render_template('csrf_error.html', message="Token keamanan tidak valid. Silakan refresh halaman dan coba lagi."), 400
    return render_template('error.html', code=400, message="Permintaan tidak valid."), 400

@app.errorhandler(403)
def handle_403(e):
    log_security_event('access_denied', current_user.nim if current_user.is_authenticated else None)
    return render_template('error.html', code=403, message="Akses ditolak. Anda tidak memiliki izin untuk mengakses halaman ini."), 403

@app.errorhandler(404)
def handle_404(e):
    return render_template('error.html', code=404, message="Halaman tidak ditemukan."), 404

@app.errorhandler(500)
def handle_500(e):
    app.logger.error(f'Server error: {e}')
    return render_template('error.html', code=500, message="Terjadi kesalahan pada server. Silakan coba lagi nanti."), 500

# ==================== INIT ====================
def init_db():
    with app.app_context():
        db.create_all()

        # Check if already initialized
        existing_admin = db.session.get(User, 'ketua')
        if existing_admin:
            return

        defaults = [
            ('is_on_air', 'true'),
            ('nama_ketua', 'ketua'),
            ('nama_wakil', 'wakil'),
            ('nim_ketua', 'ketua'),
            ('nim_wakil', 'wakil')
        ]
        for key, val in defaults:
            if not SystemConfig.query.filter_by(key=key).first():
                db.session.add(SystemConfig(key=key, value=val))

        admins = [
            ('ketua', 'Ketua Kelas', 4.0, 'admin'),
            ('wakil', 'Wakil Ketua Kelas', 4.0, 'admin')
        ]
        for nim, nama, ipk, role in admins:
            if not db.session.get(User, nim):
                user = User(
                    nim=nim,
                    nama=nama,
                    ipk=ipk,
                    password=generate_password_hash('admin123'),
                    password_changed=True,
                    role=role
                )
                db.session.add(user)

        db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
