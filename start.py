"""
SSRF VULNERABLE APP - Separate Pages
"""
import json
import os
import uuid
from datetime import datetime
from flask import Flask, render_template, request, session, redirect, jsonify
import requests

app = Flask(__name__)
app.secret_key = 'insecure-key-123'
DATABASE_FILE = 'database.json'

# ==================== DATABASE FUNCTIONS ====================
def load_db():
    """Load database from JSON file"""
    if not os.path.exists(DATABASE_FILE):
        # Initialize database
        db = {
            'users': {
                'john': {
                    'password': 'password123',
                    'role': 'user',
                    'balance': 1000,
                    'avatar': None,
                    'bio': 'Regular user',
                    'email': 'john@example.com',
                    'join_date': '2024-01-01'
                },
                'admin': {
                    'password': 'admin123',
                    'role': 'admin',
                    'balance': 5000,
                    'avatar': None,
                    'bio': 'System administrator',
                    'email': 'admin@example.com',
                    'join_date': '2024-01-01'
                }
            },
            'files': {},
            'logs': []
        }
        save_db(db)
        return db
    
    with open(DATABASE_FILE, 'r') as f:
        return json.load(f)

def save_db(db):
    """Save database to JSON file"""
    with open(DATABASE_FILE, 'w') as f:
        json.dump(db, f, indent=2)

def add_log(action, user=None):
    """Add log entry"""
    db = load_db()
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'user': user or session.get('username', 'anonymous'),
        'action': action
    }
    db['logs'].append(log_entry)
    save_db(db)

# ==================== HELPER FUNCTIONS ====================
def is_logged_in():
    return 'username' in session

def require_login():
    if not is_logged_in():
        return False, 'Please login first'
    return True, None

def get_user_data(username):
    db = load_db()
    return db['users'].get(username, {})

# ==================== PAGE ROUTES ====================

@app.route('/')
def home():
    """Home page"""
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """Login page"""
    if request.method == 'POST':
        return login_user()
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    """Sign up page"""
    if request.method == 'POST':
        return signup_user()
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard_page():
    """Dashboard page"""
    ok, error = require_login()
    if not ok:
        return redirect('/login')
    
    db = load_db()
    username = session['username']
    user = db['users'].get(username, {})
    files = db['files'].get(username, [])
    
    return render_template('dashboard.html',
        username=username,
        role=user.get('role', 'user'),
        aws_token=session.get('aws_token'),
        files=files[-5:]  # Last 5 files
    )

@app.route('/profile')
def profile_page():
    """Profile page"""
    ok, error = require_login()
    if not ok:
        return redirect('/login')
    
    db = load_db()
    username = session['username']
    user = db['users'].get(username, {})
    
    return render_template('profile.html',
        username=username,
        role=user.get('role', 'user'),
        balance=user.get('balance', 0),
        avatar_url=user.get('avatar'),
        bio=user.get('bio', ''),
        email=user.get('email', ''),
        join_date=user.get('join_date', '2024-01-01')
    )

@app.route('/upload', methods=['GET', 'POST'])
def upload_page():
    """Upload page - main SSRF vulnerability"""
    if request.method == 'GET':
        ok, error = require_login()
        if not ok:
            return redirect('/login')
        return render_template('upload.html')
    
    # POST request - handle upload
    return upload_from_url()

@app.route('/admin')
def admin_page():
    """Admin panel page"""
    token = request.args.get('token', '')
    
    if token == 'AWS_TOKEN_EXTRACTED' or session.get('aws_token') == 'AWS_TOKEN_EXTRACTED':
        # Access granted
        db = load_db()
        
        # Hide passwords
        safe_users = {}
        for username, user_data in db['users'].items():
            safe_users[username] = user_data.copy()
            safe_users[username]['password'] = '***HIDDEN***'
        
        return render_template('admin.html',
            access_granted=True,
            token=token or session.get('aws_token'),
            user_count=len(db['users']),
            total_files=sum(len(files) for files in db['files'].values()),
            users_json=json.dumps(safe_users, indent=2),
            logs_json=json.dumps(db['logs'][-10:], indent=2)
        )
    else:
        # Access denied
        return render_template('admin.html',
            access_granted=False,
            token=token
        )

# ==================== API ROUTES ====================

def login_user():
    """Handle login"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    db = load_db()
    
    if username not in db['users']:
        return 'User not found', 401
    
    if db['users'][username]['password'] != password:
        return 'Invalid password', 401
    
    session['username'] = username
    add_log(f'User logged in', username)
    return redirect('/dashboard')

def signup_user():
    """Handle sign up"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return 'Missing username or password', 400
    
    db = load_db()
    
    if username in db['users']:
        return 'User already exists', 400
    
    db['users'][username] = {
        'password': password,
        'role': 'user',
        'balance': 0,
        'avatar': None,
        'bio': 'New user',
        'email': '',
        'join_date': datetime.now().strftime('%Y-%m-%d')
    }
    db['files'][username] = []
    save_db(db)
    
    add_log(f'User signed up', username)
    return redirect('/login')

@app.route('/logout')
def logout():
    """Logout"""
    if 'username' in session:
        add_log(f'User logged out', session['username'])
        session.pop('username', None)
    return redirect('/')

def upload_from_url():
    """🚨 VULNERABLE: Upload image from URL (SSRF)"""
    ok, error = require_login()
    if not ok:
        return error, 401
    
    image_url = request.form.get('image_url')
    if not image_url:
        return 'No URL provided', 400
    
    username = session['username']
    add_log(f'Upload from URL: {image_url}', username)
    
    try:
        # 🚨 VULNERABILITY: No URL validation!
        response = requests.get(image_url, timeout=5)
        
        db = load_db()
        
        # Store file info
        file_id = str(uuid.uuid4())[:8]
        filename = f"file_{file_id}"
        
        db['files'].setdefault(username, []).append({
            'id': file_id,
            'filename': filename,
            'url': image_url,
            'size': len(response.content),
            'date': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'description': request.form.get('description', '')
        })
        
        # Check if it's AWS metadata
        if '169.254.169.254' in image_url or 'metadata' in image_url or '8080' in image_url:
            if 'Token' in response.text or 'AWS_TOKEN_EXTRACTED' in response.text:
                session['aws_token'] = 'AWS_TOKEN_EXTRACTED'
                add_log(f'AWS token extracted via SSRF', username)
        
        save_db(db)
        
        # If coming from dashboard, redirect back
        if request.form.get('from_dashboard'):
            return redirect('/dashboard')
        
        return redirect('/upload')
        
    except Exception as e:
        return f'Error: {str(e)}', 500

@app.route('/profile/update-avatar', methods=['POST'])
def update_avatar():
    """🚨 VULNERABLE: Update avatar from URL (SSRF)"""
    ok, error = require_login()
    if not ok:
        return error, 401
    
    avatar_url = request.form.get('avatar_url')
    if not avatar_url:
        return 'No URL provided', 400
    
    username = session['username']
    add_log(f'Update avatar from URL: {avatar_url}', username)
    
    try:
        # 🚨 VULNERABILITY: No URL validation!
        response = requests.get(avatar_url, timeout=5)
        
        db = load_db()
        db['users'][username]['avatar'] = avatar_url
        
        # Check if it's AWS metadata
        if '169.254.169.254' in avatar_url or 'metadata' in avatar_url or '8080' in avatar_url:
            if 'Token' in response.text or 'AWS_TOKEN_EXTRACTED' in response.text:
                session['aws_token'] = 'AWS_TOKEN_EXTRACTED'
                add_log(f'AWS token extracted via avatar SSRF', username)
        
        save_db(db)
        
        return redirect('/profile')
        
    except Exception as e:
        return f'Error: {str(e)}', 500

@app.route('/profile/update', methods=['POST'])
def update_profile():
    """Update profile info"""
    ok, error = require_login()
    if not ok:
        return error, 401
    
    username = session['username']
    bio = request.form.get('bio', '')
    email = request.form.get('email', '')
    
    db = load_db()
    db['users'][username]['bio'] = bio
    db['users'][username]['email'] = email
    save_db(db)
    
    add_log(f'Profile updated', username)
    return redirect('/profile')

@app.route('/api/preview', methods=['GET'])
def preview_url():
    """🚨 VULNERABLE: Preview any URL (SSRF)"""
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    add_log(f'Preview URL: {url}', session.get('username', 'anonymous'))
    
    try:
        # 🚨 VULNERABILITY: No URL validation!
        response = requests.get(url, timeout=3)
        
        result = {
            'url': url,
            'status': response.status_code,
            'content_type': response.headers.get('Content-Type', 'unknown'),
            'preview': response.text[:200] if response.text else 'No text content'
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== RUN APP ====================

if __name__ == '__main__':
    # Ensure templates directory exists
    os.makedirs('templates', exist_ok=True)
    
    # Ensure database exists
    load_db()
    
    print("=" * 60)
    print("SSRF VULNERABLE APP - SEPARATE PAGES")
    print("=" * 60)
    print("Running on: http://localhost:5000")
    print("\n📄 PAGES:")
    print("  /              - Home")
    print("  /login         - Login page")
    print("  /signup        - Sign up page")
    print("  /dashboard     - Dashboard")
    print("  /profile       - User profile")
    print("  /upload        - Upload image (SSRF)")
    print("  /admin         - Admin panel")
    print("\n🎯 SSRF TARGET:")
    print("  http://localhost:8080/latest/meta-data/iam/security-credentials/AdminRole")
    print("\n👤 TEST USERS: john/password123, admin/admin123")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=5000, debug=True)