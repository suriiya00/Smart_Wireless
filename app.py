import os
import eventlet
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_socketio import SocketIO, emit
import sqlite3
import hashlib
from flask_dance.contrib.google import make_google_blueprint, google
from flask_session import Session

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'Smart_Wireless/uploads'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Initialize SocketIO
socketio = SocketIO(app)

# Google OAuth Setup
google_bp = make_google_blueprint(
    client_id='555578886277-toahl49uqg96kd0mo4tmfmmsng60rod3.apps.googleusercontent.com',
    client_secret='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',
    scope=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"],
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/google_login")

# SQLite Database Setup
def create_db():
    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
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
    conn.close()

create_db()

# User class for login
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)

# User loader for Flask-login
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user_data = c.fetchone()
    conn.close()

    if user_data:
        return User(user_data[0], user_data[1], user_data[3])
    return None

# Route for login page
@app.route('/')
def index():
    return render_template('index.html')

# Route to handle registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        conn = sqlite3.connect('projector.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user_data = c.fetchone()

        if user_data:
            flash('Username already exists! Please choose a different one.')
            return redirect(url_for('register'))

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, role))
        conn.commit()
        conn.close()

        flash('Account created successfully! You can now log in.')
        return redirect(url_for('index'))

    return render_template('register.html')

# Login handler
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
    user_data = c.fetchone()
    conn.close()

    if user_data:
        user = User(user_data[0], user_data[1], user_data[3])
        login_user(user)
        return redirect(url_for('dashboard'))

    flash('Login failed. Please try again.')
    return redirect(url_for('index'))

# Google OAuth login callback
@app.route('/google_login')
def google_login():
    if not google.authorized:
        flash('Google login failed!')
        return redirect(url_for('index'))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash('Failed to fetch user info from Google.')
        return redirect(url_for('index'))

    user_info = resp.json()
    username = user_info['name']
    email = user_info['email']

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user_data = c.fetchone()

    if not user_data:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, 'google_oauth', 'student'))
        conn.commit()

    conn.close()
    user = load_user(user_data[0])
    login_user(user)

    return redirect(url_for('dashboard'))

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'teacher':
        return render_template('teacher_dashboard.html')
    return render_template('student_dashboard.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Start server
if __name__ == '__main__':
    socketio.run(app, debug=True)
