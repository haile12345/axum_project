"""
SSRF VULNERABLE APP - Separate Pages WITH Indirect File Access
"""
import json
import os
import uuid
import base64
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, session, redirect, jsonify, send_file
import requests
from urllib.parse import urlparse, quote, unquote
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'insecure-key-123'
DATABASE_FILE = 'database.json'

# ==================== NEW: INDIRECT FILE ACCESS SYSTEM ====================

class IndirectFileAccess:
    """System for accessing files via manipulable URLs"""
    
    def __init__(self):
        self.file_store = self.load_file_store()  # file_id -> file_data
        self.access_tokens = {}  # token -> file_id
        self.access_logs = []
    def load_file_store(self):
        """Load file store from database.json"""
        if not os.path.exists(DATABASE_FILE):
            return {}
        
        try:
            with open(DATABASE_FILE, 'r') as f:
                db = json.load(f)
                # Load files from the 'indirect_files' key
                return db.get('indirect_files', {})
        except:
            return {}
    def upload_file(self, username, original_filename, content, description=""):
        """Store file and generate access URLs"""
        file_id = f"file_{uuid.uuid4().hex[:8]}"
        
        # Store file
        self.file_store[file_id] = {
            'id': file_id,
            'owner': username,
            'filename': original_filename,
            'content': content,
            'description': description,
            'upload_time': datetime.now().isoformat(),
            'size': len(content),
            'access_count': 0
        }
        
        # Save to disk
        self.load_file_store()
        
        # Generate vulnerable access URLs
        get_url = self.generate_get_url(file_id, username)
        post_url = self.generate_post_url(file_id, username)
        direct_url = f"/hidden/files/{file_id}"  # Hidden endpoint
        
        return {
            'file_id': file_id,
            'get_url': get_url,
            'post_url': post_url,
            'direct_url': direct_url,
            'filename': original_filename
        }
    
    def generate_get_url(self, file_id, username):
        """🚨 Generate GET URL with weak token"""
        # Weak predictable token
        weak_token = base64.b64encode(f"{username}:{file_id}:weak".encode()).decode()
        
        # Multiple URL patterns (all vulnerable)
        patterns = [
            f"/api/access/file?fid={file_id}&tok={weak_token}",
            f"/files/get?file={file_id}&access={weak_token}",
            f"/download?id={file_id}&key={weak_token}",
            f"/api/v1/files/{file_id}?token={weak_token}",  # REST-style
            f"/file-access?f={quote(file_id)}&t={quote(weak_token)}"  # URL encoded
        ]
        
        return patterns[0]  # Return first pattern
    
    def generate_post_url(self, file_id, username):
        """🚨 Generate POST endpoint"""
        return "/api/access/file-post"
    
    def get_file(self, file_id, access_method="unknown"):
        """Retrieve file (no real auth check)"""
        if file_id in self.file_store:
            file_data = self.file_store[file_id]
            file_data['access_count'] += 1
            
            self.access_logs.append({
                'time': datetime.now().isoformat(),
                'file_id': file_id,
                'method': access_method,
                'user_agent': request.headers.get('User-Agent', 'unknown')
            })
            
            # Save updated access count
            self.load_file_store()
            
            return file_data
        return None
    
    def list_user_files(self, username):
        """List all files for a user"""
        return [f for f in self.file_store.values() if f['owner'] == username]

# Initialize
file_access = IndirectFileAccess()

# ==================== DATABASE FUNCTIONS ====================
def load_db():
    """Load database from JSON file"""
    if not os.path.exists(DATABASE_FILE):
        # Initialize database
        db = {
            'users': {
                'haile': {
                    'password': 'haile123',
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
            'indirect_files': {},  # Add this line for indirect file storage
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

# ==================== NEW: INDIRECT FILE ACCESS ENDPOINTS ====================

@app.route('/api/access/file', methods=['GET'])
def indirect_file_access_get():
    """
    🚨 VULNERABLE: Indirect file access via GET parameters
    Multiple SSRF vectors in parameter manipulation
    """
    
    # Get parameters (multiple names for same thing)
    file_id = request.args.get('fid') or request.args.get('file') or request.args.get('id') or request.args.get('f')
    token = request.args.get('tok') or request.args.get('access') or request.args.get('key') or request.args.get('token')
    
    if not file_id:
        return jsonify({'error': 'No file ID'}), 400
    
    # 🚨 VULNERABILITY 1: Weak token validation
    if token:
        try:
            # Try to decode token
            decoded = base64.b64decode(token.encode()).decode()
            if 'weak' not in decoded:  # Very weak check!
                return jsonify({'error': 'Invalid token'}), 403
        except:
            # 🚨 VULNERABILITY 2: Token might be a URL! Let's fetch it!
            try:
                
                response = requests.get(token, timeout=3)
                return jsonify({
                    'warning': 'Token looks like a URL! Fetching it...',
                    'url': token,
                    'response': response.text[:500]
                })
            except:
                pass
    
    # 🚨 VULNERABILITY 3: File ID might be a URL too!
    if file_id.startswith(('http://', 'https://')):
        try:
            response = requests.get(file_id, timeout=3)
            return jsonify({
                'warning': 'File ID is a URL! Fetching instead...',
                'url': file_id,
                'response': response.text[:500]
            })
        except Exception as e:
            return jsonify({'error': f'URL fetch failed: {str(e)}'}), 500
    
    # Get file
    file_data = file_access.get_file(file_id, 'GET')
    
    if not file_data:
        return jsonify({'error': 'File not found'}), 404
    
    return jsonify({
        'filename': file_data['filename'],
        'content': file_data['content'][:1000],
        'size': file_data['size'],
        'owner': file_data['owner'],
        'description': file_data['description'],
        'access_count': file_data['access_count']
    })

@app.route('/api/access/file-post', methods=['POST'])
def indirect_file_access_post():
    """
    🚨 VULNERABLE: Indirect file access via POST body
    SSRF through body parameter injection
    """
    
    # 🚨 VULNERABILITY: Accept multiple content types
    if request.is_json:
        data = request.get_json()
        file_id = data.get('file_id') or data.get('fid') or data.get('file')
        token = data.get('token') or data.get('access_key') or data.get('auth')
    else:
        file_id = request.form.get('file_id') or request.form.get('fid') or request.form.get('file')
        token = request.form.get('token') or request.form.get('access_key') or request.form.get('auth')
    
    if not file_id:
        return jsonify({'error': 'No file ID'}), 400
    
    # 🚨 VULNERABILITY: Token field accepts URLs!
    if token and (token.startswith('http://') or token.startswith('https://')):
        try:
            response = requests.get(token, timeout=3)
            return jsonify({
                'ssrf_warning': 'Token field contained a URL! Fetching...',
                'url': token,
                'status': response.status_code,
                'response': response.text[:500]
            })
        except Exception as e:
            return jsonify({'error': f'URL fetch failed: {str(e)}'}), 500
    
    # Get file
    file_data = file_access.get_file(file_id, 'POST')
    
    if not file_data:
        return jsonify({'error': 'File not found'}), 404
    
    return jsonify({
        'filename': file_data['filename'],
        'content': file_data['content'],
        'size': file_data['size'],
        'owner': file_data['owner']
    })

@app.route('/hidden/files/<file_id>')
def hidden_file_access(file_id):
    """
    🚨 VULNERABLE: Hidden direct file access endpoint
    No authentication at all!
    """
    
    file_data = file_access.get_file(file_id, 'DIRECT')
    
    if not file_data:
        return 'File not found', 404
    
    # Return as downloadable file
    return send_file(
        BytesIO(file_data['content'].encode()),
        as_attachment=True,
        download_name=file_data['filename']
    )

# ==================== NEW: FILE UPLOAD WITH INDIRECT ACCESS ====================

@app.route('/upload-file', methods=['GET', 'POST'])
def upload_file_page():
    """Upload files with indirect access URLs"""
    ok, error = require_login()
    if not ok:
        return redirect('/login')
    
    if request.method == 'POST':
        return handle_file_upload()
    
    return render_template('upload_file.html')

def handle_file_upload():
    """Handle file upload to indirect system"""
    username = session['username']
    
    uploaded_file = request.files.get('file')
    if not uploaded_file:
        return 'No file uploaded', 400
    
    filename = uploaded_file.filename
    content = uploaded_file.read().decode('utf-8', errors='ignore')
    description = request.form.get('description', '')
    
    # Upload to indirect system
    file_info = file_access.upload_file(username, filename, content, description)
    
    # CRITICAL: Save the indirect_files to database
    db = load_db()
    
    # Store in indirect_files section
    if 'indirect_files' not in db:
        db['indirect_files'] = {}
    
    db['indirect_files'][file_info['file_id']] = {
        'id': file_info['file_id'],
        'owner': username,
        'filename': filename,
        'content': content,
        'description': description,
        'upload_time': datetime.now().isoformat(),
        'size': len(content),
        'access_count': 0
    }
    
    # Also store reference in regular files section
    db['files'].setdefault(username, []).append({
        'id': file_info['file_id'],
        'filename': filename,
        'upload_time': datetime.now().isoformat(),
        'description': description
    })
    
    save_db(db)
    
    add_log(f'File uploaded via indirect system: {filename}', username)
    
    return render_template('upload_result.html', 
        file_info=file_info,
        username=username
    )

# ==================== ENHANCED DASHBOARD WITH INDIRECT FILES ====================

@app.route('/dashboard')
def dashboard_page():
    """Dashboard page with indirect file access"""
    ok, error = require_login()
    if not ok:
        return redirect('/login')
    
    username = session['username']
    db = load_db()
    user = db['users'].get(username, {})
    files = db['files'].get(username, [])
    
    # Get files from indirect system
    indirect_files = file_access.list_user_files(username)
    
    # Create attack examples
    attack_examples = []
    if indirect_files:
        sample_file = indirect_files[0]
        
        attack_examples = [
            {
                'name': 'Parameter Tampering',
                'description': 'Change file_id parameter to access other files',
                'example': f"/api/access/file?fid=OTHER_FILE_ID&tok=any_token",
                'hint': 'Try guessing other file IDs (file_xxxxxxx)'
            },
            {
                'name': 'URL in Token Field',
                'description': 'Put a URL in the token parameter',
                'example': f"/api/access/file?fid={sample_file['id']}&tok=http://localhost:8081/latest/meta-data/",
                'hint': 'The token parameter fetches URLs!'
            },
            {
                'name': 'POST Body Injection',
                'description': 'Inject URL in POST body token field',
                'example': 'POST /api/access/file-post\nBody: file_id=any&token=http://localhost:8081/',
                'hint': 'Token field in POST also fetches URLs'
            },
            {
                'name': 'URL Encoding Bypass',
                'description': 'Use URL encoding to bypass filters',
                'example': f"/api/access/file?fid={quote(sample_file['id'])}%26other=param&tok=weak",
                'hint': 'Try double encoding or adding extra parameters'
            }
        ]
    
    return render_template('dashboard_enhanced.html',
        username=username,
        role=user.get('role', 'user'),
        aws_token=session.get('aws_token'),
        files=files[-5:],
        indirect_files=indirect_files,
        attack_examples=attack_examples,
        file_system_stats={
            'total_files': len(file_access.file_store),
            'user_files': len(indirect_files),
            'access_logs': len(file_access.access_logs)
        }
    )

# ==================== NEW: URL ENCODING VULNERABILITY ====================

@app.route('/api/encode', methods=['GET', 'POST'])
def url_encode_service():
    """
    🚨 VULNERABLE: URL encoding/decoding service
    Can encode malicious URLs for SSRF
    """
    
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            url = data.get('url')
            action = data.get('action', 'encode')
        else:
            url = request.form.get('url')
            action = request.form.get('action', 'encode')
    else:
        url = request.args.get('url')
        action = request.args.get('action', 'encode')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        if action == 'encode':
            result = quote(url)
            message = 'URL encoded'
        elif action == 'decode':
            result = unquote(url)
            message = 'URL decoded'
        elif action == 'double_encode':
            result = quote(quote(url))
            message = 'URL double encoded'
        else:
            return jsonify({'error': 'Invalid action'}), 400
        
        # 🚨 VULNERABILITY: Try to fetch the (decoded) URL!
        try:
            response = requests.get(unquote(url) if action == 'decode' else url, timeout=3)
            fetched = True
            fetch_preview = response.text[:200]
        except:
            fetched = False
            fetch_preview = None
        
        return jsonify({
            'original': url,
            'result': result,
            'action': action,
            'message': message,
            'fetched_url': fetched,
            'fetch_preview': fetch_preview
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== KEEP YOUR EXISTING ROUTES (updated) ====================

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
    
    if token == 'flag_haile_123' or session.get('aws_token') == 'flag_haile_123':
        # Access granted
        db = load_db()
        
        # Hide passwords
        safe_users = {}
        for username, user_data in db['users'].items():
            safe_users[username] = user_data.copy()
            safe_users[username]['password'] = '***No password ***'
        
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
    ok, error = require_login()
    if not ok:
        return error, 401
    
    image_url = request.form.get('image_url')
    if not image_url:
        return 'No URL provided', 400
    
    username = session['username']
    
    try:
        response = requests.get(image_url, timeout=5)
        
        db = load_db()
        file_id = str(uuid.uuid4())[:8]
        
        db['files'].setdefault(username, []).append({
            'id': file_id,
            'filename': f"file_{file_id}",
            'url': image_url,
            'size': len(response.content),
            'date': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'description': request.form.get('description', '')
        })
        db['users'][username]['avatar'] = image_url
        # Blind SSRF: Check response for flag
        import re
        response_text = response.text
        
        # Look for flag_haile_123 or any flag_pattern
        if 'flag_haile_123' in response_text:
            session['aws_token'] = 'flag_haile_123'
        else:
            # Search for flag_pattern flag_[a-z0-9_]+
            flag_match = re.search(r'flag_[a-z0-9_]+', response_text, re.IGNORECASE)
            if flag_match:
                session['aws_token'] = flag_match.group(0)
        
        save_db(db)
        
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
        if '169.254.169.254' in avatar_url or 'metadata' in avatar_url or '8081' in avatar_url:
            if 'Token' in response.text or 'flag_haile_123' in response.text:
                session['aws_token'] = 'flag_haile_123'
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
    
    print("=" * 70)
    print("SSRF VULNERABLE APP - WITH INDIRECT FILE ACCESS")
    print("=" * 70)
    print("\n🎯 NEW FEATURES ADDED:")
    print("  1. Indirect File Access System")
    print("  2. GET Parameter Manipulation (/api/access/file)")
    print("  3. POST Body Injection (/api/access/file-post)")
    print("  4. URL Encoding Service (/api/encode)")
    print("  5. Hidden Direct Access (/hidden/files/{id})")
    
    print("\n🔓 SSRF VECTORS IN INDIRECT SYSTEM:")
    print("  • Token parameter accepts URLs (fetches them!)")
    print("  • File ID parameter also accepts URLs")
    print("  • POST body token field fetches URLs")
    print("  • Weak predictable tokens")
    print("  • No real authentication")
    
    print("\n📄 NEW ENDPOINTS:")
    print("  /api/access/file        - GET with parameter tampering")
    print("  /api/access/file-post   - POST with body injection")
    print("  /hidden/files/{id}      - Direct access (no auth)")
    print("  /api/encode             - URL encoding service")
    print("  /upload-file            - Upload to indirect system")
    
    print("\n🎯 SSRF TARGET:")
    print("  http://localhost:8081/latest/meta-data/iam/security-credentials/AdminRole")
    
    print("\n👤 TEST USERS: john/password123, admin/admin123")
    print("=" * 70)
    
    app.run(host='0.0.0.0', port=5000, debug=True)