from flask import Flask, jsonify, request, send_file
import os
import json
import paramiko
import requests
import socket

app = Flask(__name__)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Store discovered credentials
DISCOVERED_CREDS = {
    "aws": [],
    "ssh": [],
    "database": [],
    "api": []
}

# Secret token required for file access
SECRET_TOKEN = "flag_haile_123"

# ==================== TOKEN-PROTECTED FILE BROWSING ====================

@app.route('/files', methods=['GET'])
def list_files_protected():
    """List files in current directory - PROTECTED BY TOKEN"""
    token = request.args.get('token')
    
    if not token:
        return jsonify({
            "error": "Token required",
            "message": "Please provide token parameter: /files?token=YOUR_TOKEN",
            "hint": "Token can be found in AWS metadata responses"
        }), 401
    
    if token != SECRET_TOKEN:
        return jsonify({
            "error": "Wrong token",
            "message": "Invalid token provided",
            "hint": "Check AWS metadata endpoints for the correct token"
        }), 403
    
    # Token is correct, list files
    files = []
    try:
        for item in os.listdir(CURRENT_DIR):
            item_path = os.path.join(CURRENT_DIR, item)
            is_dir = os.path.isdir(item_path)
            size = os.path.getsize(item_path) if not is_dir else 0
            
            files.append({
                "name": item,
                "type": "directory" if is_dir else "file",
                "size": size,
                "path": item_path,
                "download_url": f"/files/download/{item}?token={SECRET_TOKEN}" if not is_dir else None,
                "view_url": f"/files/view/{item}?token={SECRET_TOKEN}" if item.endswith(('.py', '.txt', '.json', '.env', '.config', '.yml', '.yaml')) else None
            })
    except Exception as e:
        return jsonify({"error": f"Error listing files: {str(e)}"}), 500
    
    return jsonify({
        "current_directory": CURRENT_DIR,
        "total_files": len([f for f in files if f['type'] == 'file']),
        "total_directories": len([f for f in files if f['type'] == 'directory']),
        "files": files,
        "token_status": "valid",
        "message": "Access granted! Here are all files in the current directory."
    })

@app.route('/files/download/<path:filename>', methods=['GET'])
def download_file_protected(filename):
    """Download a file - PROTECTED BY TOKEN"""
    token = request.args.get('token')
    
    if token != SECRET_TOKEN:
        return jsonify({"error": "Wrong token", "message": "Invalid token provided"}), 403
    
    try:
        file_path = os.path.join(CURRENT_DIR, filename)
        
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
        
        if os.path.isdir(file_path):
            return jsonify({"error": "Cannot download directory"}), 400
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/files/view/<path:filename>', methods=['GET'])
def view_file_protected(filename):
    """View file content - PROTECTED BY TOKEN"""
    token = request.args.get('token')
    
    if token != SECRET_TOKEN:
        return jsonify({"error": "Wrong token", "message": "Invalid token provided"}), 403
    
    try:
        file_path = os.path.join(CURRENT_DIR, filename)
        
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
        
        if os.path.isdir(file_path):
            return jsonify({"error": "Cannot view directory"}), 400
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return jsonify({
            "filename": filename,
            "path": file_path,
            "size": len(content),
            "content": content,
            "line_count": len(content.splitlines())
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== ENHANCED AWS METADATA ====================

@app.route('/latest/meta-data/')
def metadata():
    return jsonify([
        "ami-id", "instance-type", "iam/", "hostname", "local-ipv4",
        "public-keys/", "network/", "user-data", "security-credentials/"
    ])

@app.route('/latest/meta-data/security-credentials/')
@app.route('/latest/meta-data/iam/security-credentials/')
def security_credentials():
    return jsonify(["AdminRole", "ReadOnlyRole", "PowerUserRole", "SSHKeyRole"])

@app.route('/latest/meta-data/iam/security-credentials/AdminRole')
def admin_role():
    creds = {
        "Code": "Success",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "flag_haile_123",  # FLAG HERE!
        "Expiration": "2024-12-31T23:59:59Z",
        "Permissions": "AdministratorAccess",
        "note": "Use this token to access the file system at /files?token=TOKEN"
    }
    
    # Store for auto-usage
    DISCOVERED_CREDS["aws"].append(creds)
    
    # Try to auto-use these credentials
    
    
    return jsonify(creds)

@app.route('/latest/meta-data/iam/security-credentials/ReadOnlyRole')
def read_only_role():
    creds = {
        "Code": "Success",
        "AccessKeyId": "AKIAI44QH8DHBEXAMPLE",
        "SecretAccessKey": "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
        "Token": "flag{am_fake_flag}",  # WRONG TOKEN
        "Expiration": "2024-12-31T23:59:59Z",
        "Permissions": "ReadOnlyAccess",
        "note": "This token won't work for file access"
    }
    
    DISCOVERED_CREDS["aws"].append(creds)
 
    
    return jsonify(creds)

@app.route('/latest/meta-data/iam/security-credentials/PowerUserRole')
def power_user_role():
    creds = {
        "Code": "Success",
        "AccessKeyId": "AKIAEXAMPLE123456",
        "SecretAccessKey": "bPxRfiCYEXAMPLEKEY/je7MtGbClwBF/2Zp9Utk",
        "Token": "flag{am_fake_flag}",  # WRONG TOKEN
        "Expiration": "2024-12-31T23:59:59Z",
        "Permissions": "PowerUserAccess",
        "note": "This token won't work for file access"
    }
    
    DISCOVERED_CREDS["aws"].append(creds)
   
    
    return jsonify(creds)

@app.route('/latest/meta-data/iam/security-credentials/SSHKeyRole')
def ssh_key_role():
    """AWS role that contains SSH private key"""
    # Generate a fake SSH key
    ssh_private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAtCqow5WKXpy2c8bXcQrFQZ2YK3LgN8gK6cJ7qV7W8i1kLzT
...fake ssh key for demonstration...
-----END RSA PRIVATE KEY-----"""
    
    creds = {
        "Code": "Success",
        "AccessKeyId": "AKIASSSHKEYEXAMPLE",
        "SecretAccessKey": "ssh-key-example-secret",
        "Token": "flag_haile_123",  # FLAG HERE TOO!
        "Expiration": "2024-12-31T23:59:59Z",
        "SSHPrivateKey": ssh_private_key,
        "SSHUsername": "ubuntu",
        "SSHHost": "10.0.0.1",
        "note": "Use this token to access the file system at /files?token=TOKEN"
    }
    
    DISCOVERED_CREDS["aws"].append(creds)
    DISCOVERED_CREDS["ssh"].append({
        "host": "10.0.0.1",
        "username": "ubuntu",
        "private_key": ssh_private_key
    })
    
    # Try SSH with this key
    auto_try_ssh("10.0.0.1", "ubuntu", private_key=ssh_private_key)
    
    return jsonify(creds)

# ==================== SSH KEYS IN METADATA ====================

@app.route('/latest/meta-data/public-keys/')
def public_keys():
    return jsonify(["0", "1", "admin-key"])

@app.route('/latest/meta-data/public-keys/0')
def public_key_0():
    """SSH public key - often contains private key or password hints"""
    return "ssh-rsa AAAAB3NzaC1yc2E... ubuntu@ip-10-0-0-1\nPassword hint: 'admin123'"

@app.route('/latest/meta-data/public-keys/admin-key')
def admin_ssh_key():
    """SSH key that might work with discovered passwords"""
    key_data = {
        "public_key": "ssh-rsa AAAAB3NzaC1yc2E... admin@internal",
        "private_key_fragment": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
        "hosts": ["10.0.0.1", "192.168.1.1", "localhost"],
        "username": "admin",
        "password_hint": "Try 'password123' or 'admin'"
    }
    
    # Try SSH with common passwords
    for host in key_data["hosts"]:
        for password in ["password123", "admin", "Admin123", "password"]:
            auto_try_ssh(host, "admin", password=password)
    
    return jsonify(key_data)

# ==================== USER DATA (OFTEN CONTAINS CREDS) ====================

@app.route('/latest/user-data')
def user_data():
    """User data often contains configuration, passwords, API keys"""
    user_data_content = """#!/bin/bash
# Instance initialization script
DB_PASSWORD="SuperSecretDBPass123!"
API_KEY="sk_live_1234567890abcdef"
SSH_PASSWORD="ServerAdminPass!2024"
AWS_ACCESS_KEY="AKIAUSERDATAEXAMPLE"
AWS_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/UserDataExampleKey"

# Database connection
mysql -u root -p"SuperSecretDBPass123!" -e "CREATE DATABASE appdb;"

# Application config
echo "API_KEY=sk_live_1234567890abcdef" >> /etc/app/config.env
echo "ADMIN_PASSWORD=CyberSecurity2024!" >> /etc/app/config.env
"""
    
    # Extract and try credentials
    extracted = extract_credentials_from_text(user_data_content)
    
    for cred_type, cred_list in extracted.items():
        DISCOVERED_CREDS[cred_type].extend(cred_list)
    
    # Try database with discovered password
    for db_cred in extracted.get("database", []):
        auto_try_database(
            host="localhost",
            username="root",
            password=db_cred.get("password"),
            database="mysql"
        )
    
    return user_data_content

# ==================== NETWORK INFO ====================

@app.route('/latest/meta-data/network/interfaces/macs/')
def network_macs():
    return jsonify(["02:00:00:00:00:01"])

@app.route('/latest/meta-data/network/interfaces/macs/02:00:00:00:00:01/local-ipv4s')
def local_ips():
    """Reveal internal IPs that can be targeted"""
    ips = ["10.0.0.1", "192.168.1.100", "172.31.32.1"]
    
    # Try SSH on discovered IPs with common credentials
    for ip in ips:
        for user in ["ubuntu", "admin", "root", "ec2-user"]:
            for password in ["password123", "admin", "", "ubuntu"]:
                auto_try_ssh(ip, user, password=password)
    
    return jsonify(ips)

# ==================== FILE SEARCH ENDPOINT ====================

@app.route('/search/files', methods=['GET'])
def search_files():
    """Search for specific file types - PROTECTED BY TOKEN"""
    token = request.args.get('token')
    query = request.args.get('q', '')
    
    if token != SECRET_TOKEN:
        return jsonify({"error": "Wrong token", "message": "Invalid token provided"}), 403
    
    try:
        matching_files = []
        for root, dirs, files in os.walk(CURRENT_DIR):
            for file in files:
                if query.lower() in file.lower():
                    file_path = os.path.join(root, file)
                    matching_files.append({
                        "name": file,
                        "path": file_path,
                        "size": os.path.getsize(file_path),
                        "relative_path": os.path.relpath(file_path, CURRENT_DIR)
                    })
        
        return jsonify({
            "query": query,
            "results_found": len(matching_files),
            "files": matching_files[:50]  # Limit results
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==================== AUTO-USAGE FUNCTIONS ====================

def auto_try_ssh(host, username, password=None, private_key=None):
    """Automatically try SSH with discovered credentials"""
    try:
        print(f"\n🔐 ATTEMPTING SSH ACCESS:")
        print(f"   Host: {host}, User: {username}")
        
        if password:
            print(f"   Trying password: {'*' * len(password)}")
            # Simulate SSH attempt
            if password in ["password123", "admin", "Admin123", "ubuntu"]:
                print(f"   ✅ SUCCESS! SSH access with password '{password}'")
                return True
        elif private_key:
            print(f"   Trying SSH key authentication")
            # Simulate key-based auth
            print(f"   ✅ SUCCESS! SSH access with private key")
            return True
        
        print(f"   ❌ SSH access failed")
        return False
        
    except Exception as e:
        print(f"   ❌ SSH error: {str(e)[:100]}")
        return False

def auto_try_database(host, username, password, database):
    """Automatically try database access with discovered credentials"""
    try:
        print(f"\n🔐 ATTEMPTING DATABASE ACCESS:")
        print(f"   Host: {host}, DB: {database}, User: {username}")
        print(f"   Password: {'*' * len(password) if password else 'None'}")
        
        # Simulate database connection
        if password == "SuperSecretDBPass123!":
            print(f"   ✅ SUCCESS! Database access granted")
            print(f"   📊 Found tables: users, passwords, transactions")
            return True
        
        print(f"   ❌ Database access failed")
        return False
        
    except Exception as e:
        print(f"   ❌ Database error: {str(e)[:100]}")
        return False

def extract_credentials_from_text(text):
    """Extract potential credentials from text"""
    import re
    
    credentials = {
        "aws": [],
        "ssh": [],
        "database": [],
        "api": []
    }
    
    # Look for AWS keys
    aws_patterns = [
        (r'AWS_ACCESS_KEY[=:\s]+["\']?([A-Z0-9]{20})["\']?', 'AccessKeyId'),
        (r'AWS_SECRET_KEY[=:\s]+["\']?([A-Za-z0-9/+]{40})["\']?', 'SecretAccessKey'),
        (r'AKIA[A-Z0-9]{16}', 'AccessKeyId'),
    ]
    
    # Look for passwords
    password_patterns = [
        (r'PASSWORD[=:\s]+["\']?([^"\'\s]+)["\']?', 'password'),
        (r'DB_PASS[=:\s]+["\']?([^"\'\s]+)["\']?', 'database_password'),
        (r'passwd[=:\s]+["\']?([^"\'\s]+)["\']?', 'password'),
    ]
    
    # Look for API keys
    api_patterns = [
        (r'API_KEY[=:\s]+["\']?([^"\'\s]{20,})["\']?', 'api_key'),
        (r'sk_[live|test]_[A-Za-z0-9]{20,}', 'stripe_key'),
        (r'[0-9a-f]{32}', 'md5_hash_possible_key'),
    ]
    
    # Extract AWS credentials
    for pattern, key_type in aws_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            credentials["aws"].append({key_type: match})
    
    # Extract passwords
    for pattern, key_type in password_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for match in matches:
            if len(match) > 4:  # Reasonable password length
                credentials["database"].append({"password": match})
    
    # Extract API keys
    for pattern, key_type in api_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            credentials["api"].append({key_type: match})
    
    return credentials

# ==================== CONFIG FILES WITH CREDS ====================

@app.route('/config/app-config')
def app_config():
    """Simulate application config file with credentials"""
    config = {
        "database": {
            "host": "db.internal.company.com",
            "port": 5432,
            "name": "production_db",
            "username": "app_user",
            "password": "P@ssw0rd!2024",
            "ssl": True
        },
        "redis": {
            "host": "redis.internal",
            "password": "RedisPass123",
            "port": 6379
        },
        "aws": {
            "access_key": "AKIACONFIGEXAMPLE",
            "secret_key": "ConfigExampleSecretKey123",
            "region": "us-east-1"
        },
        "api_keys": {
            "stripe": "sk_live_configexample123",
            "sendgrid": "SG.configexample.sendgrid",
            "google_maps": "AIzaConfigExampleKey123"
        }
    }
    
    # Try database with these credentials
    auto_try_database(
        host=config["database"]["host"],
        username=config["database"]["username"],
        password=config["database"]["password"],
        database=config["database"]["name"]
    )
    
    # Try Redis
    print(f"\n🔐 ATTEMPTING REDIS ACCESS:")
    print(f"   Host: {config['redis']['host']}")
    print(f"   Password: {'*' * len(config['redis']['password'])}")
    print(f"   ✅ SUCCESS! Redis access granted")
    
    return jsonify(config)

# ==================== CREDENTIALS SUMMARY ====================

@app.route('/discovered-creds')
def discovered_creds():
    """Show all credentials discovered so far"""
    return jsonify({
        "total_credentials_found": sum(len(v) for v in DISCOVERED_CREDS.values()),
        "aws_credentials": DISCOVERED_CREDS["aws"],
        "ssh_credentials": DISCOVERED_CREDS["ssh"],
        "database_credentials": DISCOVERED_CREDS["database"],
        "api_keys": DISCOVERED_CREDS["api"],
        "next_steps": [
            "Use AWS credentials to access S3/EC2",
            "Try SSH with discovered keys/passwords",
            "Access databases with found credentials",
            "Use API keys for external services"
        ]
    })

# ==================== SHELL ACCESS SIMULATION ====================

@app.route('/shell-access')
def shell_access():
    """Simulate gaining shell access after credential theft"""
    
    # Simulate what an attacker could do after getting access
    shell_commands = [
        {"command": "whoami", "output": "root"},
        {"command": "pwd", "output": "/root"},
        {"command": "ls -la", "output": "total 48\ndrwxr-xr-x  5 root root 4096 Jan  1 00:00 .\ndrwxr-xr-x 19 root root 4096 Jan  1 00:00 ..\n-rw-------  1 root root 1234 Jan  1 00:00 .bash_history\n-rw-r--r--  1 root root 3106 Jan  1 00:00 .bashrc\n-rw-r--r--  1 root root  161 Jan  1 00:00 .profile\n-rw-r--r--  1 root root  512 Jan  1 00:00 secret_keys.txt"},
        {"command": "cat /etc/passwd", "output": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash"},
        {"command": "cat secret_keys.txt", "output": "STRIPE_SECRET_KEY=sk_live_abcdef123456\nDATABASE_URL=postgres://admin:FinalPassword123@db.internal:5432/production\nSSH_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n..."},
    ]
    
    return jsonify({
        "message": "Shell access achieved using stolen credentials!",
        "credentials_used": DISCOVERED_CREDS["ssh"][-1] if DISCOVERED_CREDS["ssh"] else "password123",
        "shell_session": shell_commands,
        "data_exfiltrated": [
            "User credentials",
            "Database connection strings",
            "API keys",
            "Configuration files"
        ]
    })

# ==================== HOME PAGE WITH INSTRUCTIONS ====================

@app.route('/')
def home():
    return """
    <h1>SSRF AWS Credential Server</h1>
    <p>This server simulates AWS metadata service that can be exploited via SSRF.</p>
    
    <h2>🏴‍☠️ CTF Challenge:</h2>
    <ol>
        <li>Find the secret token in AWS metadata</li>
        <li>Use it to access the file system</li>
        <li>Find the flag in the files</li>
    </ol>
    
    <h2>🔓 AWS Metadata Endpoints (for SSRF):</h2>
    <ul>
        <li><a href="/latest/meta-data/">/latest/meta-data/</a></li>
        <li><a href="/latest/meta-data/iam/security-credentials/">/latest/meta-data/iam/security-credentials/</a></li>
        <li><a href="/latest/meta-data/iam/security-credentials/AdminRole">/latest/meta-data/iam/security-credentials/AdminRole</a></li>
        <li><a href="/latest/meta-data/iam/security-credentials/SSHKeyRole">/latest/meta-data/iam/security-credentials/SSHKeyRole</a></li>
    </ul>
    
    <h2>🔐 Protected File Access:</h2>
    <ul>
        <li><code>/files?token=TOKEN</code> - List all files (requires token)</li>
        <li><code>/files/download/FILENAME?token=TOKEN</code> - Download file</li>
        <li><code>/files/view/FILENAME?token=TOKEN</code> - View file content</li>
        <li><code>/search/files?token=TOKEN&q=QUERY</code> - Search files</li>
    </ul>
    
    <h2>🎯 Goal:</h2>
    <p>Use SSRF to get the token from AWS metadata, then use it to access the file system!</p>
    """

# ==================== MAIN ====================

if __name__ == '__main__':
    print("=" * 70)
    print("SSRF AWS CREDENTIAL SERVER WITH FILE ACCESS CHALLENGE")
    print("=" * 70)
    print("\n🎯 CTF CHALLENGE:")
    print("   1. Find the secret token in AWS metadata")
    print("   2. Use token to access file system at /files?token=TOKEN")
    print("   3. Explore files to find the flag")
    
    print("\n🔓 VULNERABLE ENDPOINTS (for SSRF):")
    print("   /latest/meta-data/iam/security-credentials/* - AWS IAM roles with tokens")
    
    print("\n🔐 PROTECTED ENDPOINTS (require token):")
    print("   /files?token=TOKEN - List all files in directory")
    print("   /files/download/*?token=TOKEN - Download files")
    print("   /files/view/*?token=TOKEN - View file contents")
    print("   /search/files?token=TOKEN&q=query - Search files")
    
    print("\n💡 HINTS:")
    print("   • The token is: flag_haile_123")
    print("   • Token is found in AdminRole and SSHKeyRole endpoints")
    print("   • Wrong tokens will be rejected with 'Wrong token' message")
    
    print("\n📁 Current directory files:")
    try:
        files = os.listdir(CURRENT_DIR)
        for f in files[:10]:  # Show first 10 files
            print(f"   - {f}")
        if len(files) > 10:
            print(f"   ... and {len(files) - 10} more files")
    except:
        print("   Could not list directory")
    
    print("\n🌐 Server running on: http://localhost:8081")
    print("📚 Full instructions: http://localhost:8081/")
    print("=" * 70)
    
    app.run(host='0.0.0.0', port=8081, debug=False)