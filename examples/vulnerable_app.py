#!/usr/bin/env python3
"""
Vulnerable Web Application - Do testowania skuteczności Hexstrike
UWAGA: NIE URUCHAMIAĆ W PRODUKCJI! Celowo zawiera podatności!

Podatności:
1. SQL Injection
2. XSS (Reflected)
3. Command Injection
4. Path Traversal
5. IDOR (Insecure Direct Object Reference)
6. Missing Security Headers
"""

from flask import Flask, request, render_template_string, jsonify
import sqlite3
import os
import subprocess

app = Flask(__name__)

# Baza danych in-memory z przykładowymi danymi
def init_db():
    conn = sqlite3.connect(':memory:', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE secrets (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            secret TEXT
        )
    ''')

    # Przykładowe dane
    users = [
        (1, 'admin', 'admin123', 'admin@vulnerable.com', 'admin'),
        (2, 'user1', 'pass123', 'user1@test.com', 'user'),
        (3, 'user2', 'qwerty', 'user2@test.com', 'user'),
    ]
    secrets = [
        (1, 1, 'Admin secret key: FLAG{admin_secret_key}'),
        (2, 2, 'User1 API token: sk-123456'),
        (3, 3, 'User2 credit card: 4111-1111-1111-1111'),
    ]

    cursor.executemany('INSERT INTO users VALUES (?, ?, ?, ?, ?)', users)
    cursor.executemany('INSERT INTO secrets VALUES (?, ?, ?)', secrets)
    conn.commit()
    return conn

db = init_db()

# HTML Templates
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head><title>Vulnerable Login</title></head>
<body>
    <h1>Login Page</h1>
    <form method="GET" action="/login">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <input type="submit" value="Login">
    </form>
    {% if message %}
    <p style="color: red;">{{ message|safe }}</p>
    {% endif %}
</body>
</html>
'''

@app.route('/')
def index():
    return '''
    <h1>Vulnerable Web Application</h1>
    <p>Endpoints do testowania:</p>
    <ul>
        <li><a href="/login">/login</a> - SQL Injection + XSS</li>
        <li><a href="/search?q=test">/search?q=test</a> - XSS Reflected</li>
        <li><a href="/file?name=test.txt">/file?name=test.txt</a> - Path Traversal</li>
        <li><a href="/ping?host=localhost">/ping?host=localhost</a> - Command Injection</li>
        <li><a href="/user/1">/user/1</a> - IDOR</li>
        <li><a href="/api/data">/api/data</a> - Missing Security Headers</li>
    </ul>
    '''

# VULNERABILITY 1: SQL Injection
@app.route('/login')
def login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')

    if username and password:
        # VULNERABLE: Direct string interpolation in SQL
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

        try:
            cursor = db.cursor()
            cursor.execute(query)
            user = cursor.fetchone()

            if user:
                message = f"Welcome {user[1]}! Your email is {user[3]}"
            else:
                message = "Invalid credentials"
        except Exception as e:
            message = f"Error: {str(e)}"

        return render_template_string(LOGIN_TEMPLATE, message=message)

    return render_template_string(LOGIN_TEMPLATE, message=None)

# VULNERABILITY 2: XSS (Reflected)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: No escaping of user input
    html = f'''
    <html>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <p>No results found.</p>
    </body>
    </html>
    '''
    return html

# VULNERABILITY 3: Path Traversal
@app.route('/file')
def read_file():
    filename = request.args.get('name', '')

    if not filename:
        return "Specify ?name=filename"

    try:
        # VULNERABLE: No path sanitization
        with open(filename, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error: {str(e)}"

# VULNERABILITY 4: Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host', '')

    if not host:
        return "Specify ?host=hostname"

    try:
        # VULNERABLE: Direct command execution with user input
        result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True, timeout=5)
        return f"<pre>{result}</pre>"
    except subprocess.TimeoutExpired:
        return "Ping timeout"
    except Exception as e:
        return f"Error: {str(e)}"

# VULNERABILITY 5: IDOR (Insecure Direct Object Reference)
@app.route('/user/<int:user_id>')
def get_user_secret(user_id):
    # VULNERABLE: No access control - any user can access any secret
    cursor = db.cursor()
    cursor.execute(f"SELECT s.secret, u.username FROM secrets s JOIN users u ON s.user_id = u.id WHERE s.user_id = {user_id}")
    result = cursor.fetchone()

    if result:
        return f"<h1>Secret for user {result[1]}</h1><p>{result[0]}</p>"
    return "User not found"

# VULNERABILITY 6: Missing Security Headers
@app.route('/api/data')
def api_data():
    # VULNERABLE: No security headers (X-Frame-Options, CSP, etc.)
    return jsonify({
        "data": "sensitive information",
        "api_key": "sk-secret-123456",
        "database": "mongodb://admin:pass@localhost/prod"
    })

if __name__ == '__main__':
    print("="*80)
    print("🚨 VULNERABLE WEB APPLICATION 🚨")
    print("="*80)
    print("\nTa aplikacja zawiera CELOWE podatności do testowania!")
    print("NIE URUCHAMIAJ W PRODUKCJI!")
    print("\nPodatności:")
    print("1. SQL Injection: /login?username=admin'--&password=x")
    print("2. XSS: /search?q=<script>alert('XSS')</script>")
    print("3. Path Traversal: /file?name=../../../../etc/passwd")
    print("4. Command Injection: /ping?host=localhost;id")
    print("5. IDOR: /user/1 (access other users' secrets)")
    print("6. Missing Headers: /api/data")
    print("\nUruchamiam na http://127.0.0.1:5000")
    print("="*80 + "\n")

    app.run(host='127.0.0.1', port=5000, debug=True)
