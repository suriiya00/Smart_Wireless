import os
import eventlet
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_socketio import SocketIO, emit
import sqlite3
import hashlib

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Strong secret key for session management
app.config['UPLOAD_FOLDER'] = 'uploads'  # Directory to store uploaded files
socketio = SocketIO(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# SQLite Database Setup
def create_db():
    with sqlite3.connect('projector.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            uploaded_by TEXT NOT NULL
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS screen_share_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            request_status TEXT NOT NULL DEFAULT 'pending',
            request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(student_id) REFERENCES users(id)
        )''')
        conn.commit()

create_db()

# User class for login
class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect('projector.db') as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id=?", (user_id,))
        user_data = c.fetchone()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[3])
    return None

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = request.form['role']

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        with sqlite3.connect('projector.db') as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE username=?", (username,))
            if c.fetchone():
                flash('Username already exists!')
                return redirect(url_for('register'))
            c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
                      (username, hashed_password, email, role))
            conn.commit()
        flash('Account created successfully!')
        return redirect(url_for('index'))
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    with sqlite3.connect('projector.db') as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
        user_data = c.fetchone()
        if user_data:
            user = User(user_data[0], user_data[1], user_data[2], user_data[3])
            login_user(user)
            return redirect(url_for('dashboard'))
    flash('Login failed. Please try again.')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'teacher':
        return render_template('teacher_dashboard.html')
    return render_template('student_dashboard.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if current_user.role != 'student':
        return 'Only students can upload files.', 403

    file = request.files.get('file')
    if not file:
        flash('No file selected!')
        return redirect(url_for('dashboard'))
    
    filename = file.filename
    if not filename:
        flash('Invalid file!')
        return redirect(url_for('dashboard'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    with sqlite3.connect('projector.db') as conn:
        c = conn.cursor()
        c.execute("INSERT INTO uploaded_files (filename, uploaded_by) VALUES (?, ?)",
                  (filename, current_user.username))
        conn.commit()

    flash('File uploaded successfully!')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    socketio.run(app, debug=True)
