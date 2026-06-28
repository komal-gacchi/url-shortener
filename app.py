import re 
import os
import string
import random
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-super-secret-resume-key'

# --- DYNAMIC DATABASE CONFIGURATION FOR DEPLOYMENT ---
if os.environ.get('DATABASE_URL'):
    database_url = os.environ.get('DATABASE_URL').replace("postgres://", "postgresql://", 1)
else:
    database_url = 'sqlite:///url_shortener.db'

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    security_question = db.Column(db.String(200), nullable=False, default="What is your pet's name?")
    security_answer = db.Column(db.String(200), nullable=False, default="admin")
    
    urls = db.relationship('URL', backref='owner', lazy=True, cascade="all, delete-orphan")

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.Text, nullable=False)
    short_code = db.Column(db.String(20), unique=True, nullable=False)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # ✅ NAYE COLUMNS SUCESSFULLY ADDED HERE
    start_date = db.Column(db.String(50), nullable=True)
    expiry_date = db.Column(db.String(50), nullable=True)
    password_hash = db.Column(db.String(200), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_short_code(length=6):
    characters = string.ascii_letters + string.digits
    while True:
        code = ''.join(random.choice(characters) for _ in range(length))
        if not URL.query.filter_by(short_code=code).first():
            return code

# --- AUTHENTICATION ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    username_val = ""
    email_val = ""
        
    if request.method == 'POST':
        username_val = request.form.get('username', '').strip()
        email_val = request.form.get('email', '').strip()
        password = request.form.get('password')

        if User.query.filter_by(username=username_val).first() or User.query.filter_by(email=email_val).first():
            flash('Username or Email already exists.', 'error')
            return render_template('register.html', username=username_val, email=email_val)

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html', username=username_val, email=email_val)
            
        if not re.search(r"[A-Z]", password):
            flash('Password must contain at least one uppercase letter (A-Z).', 'error')
            return render_template('register.html', username=username_val, email=email_val)
            
        if not re.search(r"[a-z]", password):
            flash('Password must contain at least one lowercase letter (a-z).', 'error')
            return render_template('register.html', username=username_val, email=email_val)
            
        if not re.search(r"\d", password):
            flash('Password must contain at least one digit (0-9).', 'error')
            return render_template('register.html', username=username_val, email=email_val)
            
        if not re.search(r"[@$!%*?&]", password):
            flash('Password must contain at least one special character (@, $, !, %, *, ?, &).', 'error')
            return render_template('register.html', username=username_val, email=email_val)

        hashed_password = generate_password_hash(password, method='scrypt')
        is_first_user = User.query.count() == 0
        
        new_user = User(username=username_val, email=email_val, password_hash=hashed_password, is_admin=is_first_user)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', username=username_val, email=email_val)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        
        flash('Invalid credentials.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email').strip()
        answer = request.form.get('security_answer').strip().lower()
        new_password = request.form.get('new_password')

        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Email not found.', 'error')
            return redirect(url_for('forgot_password'))

        if check_password_hash(user.security_answer, answer):
            if len(new_password) < 8:
                flash('New password must be at least 8 characters long.', 'error')
                return redirect(url_for('forgot_password'))
                
            user.password_hash = generate_password_hash(new_password, method='scrypt')
            db.session.commit()
            flash('Password reset successful! Please login with your new password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Incorrect security answer.', 'error')
            return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)

# --- USER PROFILE SETTINGS API ---

@app.route('/api/profile/update', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json() or {}
    new_username = data.get('username', '').strip()
    new_email = data.get('email', '').strip()

    if not new_username or not new_email:
        return jsonify({'error': 'Fields cannot be left empty.'}), 400

    existing_user = User.query.filter(User.id != current_user.id).filter(
        (User.username == new_username) | (User.email == new_email)
    ).first()
    
    if existing_user:
        return jsonify({'error': 'Username or Email is already taken.'}), 400

    current_user.username = new_username
    current_user.email = new_email
    db.session.commit()

    return jsonify({'message': 'Profile updated successfully.'})

# --- ADMIN PANEL ROUTES ---

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        return "Access Denied: Admins Only", 403
    
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    if current_user.id == user_id:
        flash("You cannot delete your own admin account!", "error")
        return redirect(url_for('admin_panel'))
        
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} deleted successfully.", "success")
        
    return redirect(url_for('admin_panel'))

# --- CORE URL SHORTENER API (UPDATED FOR ADVANCED INPUTS) ---

@app.route('/api/shorten', methods=['POST'])
@login_required
def shorten_url():
    data = request.get_json() or {}
    original_url = data.get('url', '').strip()
    custom_alias = data.get('alias', '').strip()
    
    # ✅ ACCEPTING ADVANCED ATTRIBUTES
    start_date = data.get('start_date')
    expiry_date = data.get('expiry_date')
    password = data.get('password')

    if not original_url:
        return jsonify({'error': 'URL is required'}), 400

    if custom_alias:
        short_code = custom_alias
        if URL.query.filter_by(short_code=short_code).first():
            return jsonify({'error': 'Custom alias already exists'}), 400
    else:
        short_code = generate_short_code()

    # Password encryption if provided
    p_hash = generate_password_hash(password, method='scrypt') if password else None

    created_at = datetime.now().strftime("%d %b %Y, %I:%M %p")
    
    # ✅ DB ROW INSERT WITH ADVANCED OPTIONS
    new_url = URL(
        original_url=original_url, 
        short_code=short_code, 
        created_at=created_at, 
        user_id=current_user.id,
        start_date=start_date,
        expiry_date=expiry_date,
        password_hash=p_hash
    )
    
    db.session.add(new_url)
    db.session.commit()

    return jsonify({
        'original_url': original_url,
        'short_url': f"{request.host_url}{short_code}",
        'clicks': 0,
        'created_at': created_at
    }), 201

@app.route('/api/links', methods=['GET'])
@login_required
def get_links():
    user_urls = URL.query.filter_by(user_id=current_user.id).order_by(URL.id.desc()).all()
    return jsonify([{
        'id': url.id,
        'original_url': url.original_url,
        'short_url': f"{request.host_url}{url.short_code}",
        'clicks': url.clicks,
        'created_at': url.created_at
    } for url in user_urls])

@app.route('/api/links/<int:link_id>', methods=['DELETE'])
@login_required
def delete_link(link_id):
    url = URL.query.filter_by(id=link_id, user_id=current_user.id).first()
    if not url: return jsonify({'error': 'Unauthorized'}), 404
    db.session.delete(url)
    db.session.commit()
    return jsonify({'message': 'Deleted successfully'})

# --- PASSWORD CHECK AND REDIRECTION ENGINE ---

@app.route('/<short_code>', methods=['GET', 'POST'])
def redirect_to_url(short_code):
    url = URL.query.filter_by(short_code=short_code).first()
    if not url:
        return "URL not found", 404

    # 1. Check Scheduling (Start Date & Expiry Date)
    current_time_str = datetime.now().isoformat() # Format: YYYY-MM-DDTHH:MM
    if url.start_date and current_time_str < url.start_date:
        return "This link has not started yet.", 403
    if url.expiry_date and current_time_str > url.expiry_date:
        return "This link has expired.", 410

    # 2. Check Password Protection
    if url.password_hash:
        if request.method == 'POST':
            entered_password = request.form.get('link_password')
            if check_password_hash(url.password_hash, entered_password):
                # Click increment and redirect if password matched
                url.clicks += 1
                db.session.commit()
                return redirect(url.original_url)
            else:
                flash("Incorrect password! Please try again.", "error")
                return render_template('password_prompt.html', short_code=short_code)
        
        # Agar GET request hai toh pehle password maangne ka form dikhao
        return render_template('password_prompt.html', short_code=short_code)

    # 3. Normal Link (No password)
    url.clicks += 1
    db.session.commit()
    return redirect(url.original_url)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)