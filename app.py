import os
import eventlet
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_socketio import SocketIO, emit
import sqlite3
import hashlib
from flask_dance.contrib.google import make_google_blueprint, google
from flask_login import login_user

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'Smart_Wireless/uploads'  # Directory to store uploaded files
socketio = SocketIO(app)

# Google OAuth Setup
google_bp = make_google_blueprint(
    client_id='555578886277-toahl49uqg96kd0mo4tmfmmsng60rod3.apps.googleusercontent.com',
    client_secret='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',
    redirect_to='https://smart-wireless.onrender.com/google_login'  # This should match the route for the callback
)
app.register_blueprint(google_bp, url_prefix='/google_login')

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

        # Check if username already exists
        conn = sqlite3.connect('projector.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user_data = c.fetchone()

        if user_data:
            flash('Username already exists! Please choose a different one.')
            return redirect(url_for('register'))

        # Hash the password before storing it
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Insert new user into the database
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

    # Hash the input password and check against the stored hashed password
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
@app.route('/google_login/google/authorized')
def google_login():
    if not google.authorized:
        flash('Google login failed!')
        return redirect(url_for('index'))
    
    # Fetch user info from Google
    resp = google.get('/oauth2/v2/userinfo')  # Updated to the correct endpoint
    assert resp.ok, resp.text
    user_info = resp.json()

    username = user_info['name']  # Changed from 'displayName' to 'name'
    email = user_info['email']  # Adjusted for correct field

    # Check if the user exists in the database or register new user
    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user_data = c.fetchone()

    if user_data is None:
        # Register the new user (You may want to adjust this based on your logic)
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  (username, 'google_oauth_password', 'student'))
        conn.commit()
        conn.close()
    
    # Log in the user
    user = User(user_data[0], username, 'student')
    login_user(user)
    
    return redirect(url_for('dashboard'))

# Dashboard route (teacher or student)
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'teacher':
        return render_template('teacher_dashboard.html')
    else:
        return render_template('student_dashboard.html')

# File upload handler
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if current_user.role != 'student':
        return 'Only students can upload files.' 
    
    file = request.files['file']
    filename = file.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("INSERT INTO uploaded_files (filename, uploaded_by) VALUES (?, ?)", (filename, current_user.username))
    conn.commit()
    conn.close()

    return 'File uploaded successfully!'

# Presentation Control Handlers
@app.route('/next')
def next_slide():
    # Handle next slide
    return 'Next slide'

@app.route('/prev')
def prev_slide():
    # Handle previous slide
    return 'Previous slide'

@app.route('/pause')
def pause_presentation():
    # Handle pause
    return 'Presentation paused'

@app.route('/resume')
def resume_presentation():
    # Handle resume
    return 'Presentation resumed'

@app.route('/control')
@login_required
def control_page():
    return render_template('control.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Admin Routes for Teachers
@app.route('/admin/users')
@login_required
def view_users():
    if current_user.role not in ['teacher', 'admin']:
        return "Access Denied", 403  # Restrict access to teachers/admins only
    
    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users")  # Fetch user details
    users = c.fetchall()
    conn.close()

    return render_template('view_users.html', users=users)

@app.route('/admin/files')
@login_required
def view_files():
    if current_user.role not in ['teacher', 'admin']:
        return "Access Denied", 403  # Restrict access to teachers/admins only
    
    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    c.execute("SELECT id, filename, uploaded_by FROM uploaded_files")  # Fetch file details
    files = c.fetchall()
    conn.close()

    return render_template('view_files.html', files=files)

@app.route('/view_screen_share_requests')
@login_required
def view_screen_share_requests():
    if current_user.role != 'teacher':
        return "Access Denied", 403  # Only teachers can view requests

    conn = sqlite3.connect('projector.db')
    c = conn.cursor()
    # Fetch pending screen-sharing requests
    c.execute("SELECT r.id, u.username, r.request_time FROM screen_share_requests r JOIN users u ON r.student_id = u.id WHERE r.request_status = 'pending'")
    requests = c.fetchall()
    conn.close()

    return render_template('teacher_dashboard.html', requests=requests)

@app.route('/request_screen_share', methods=['POST'])
@login_required
def request_screen_share():
    if current_user.role != 'student':
        return "Access Denied", 403
    conn = sqlite3.connect('projector.db')
    c = conn.cursor()

    # Check if a pending request already exists for this student
    c.execute("SELECT * FROM screen_share_requests WHERE student_id = ? AND request_status = 'pending'", (current_user.id,))
    existing_request = c.fetchone()

    if existing_request:
        flash("You already have a pending screen-sharing request.")
        return redirect(url_for('dashboard'))

    c.execute("INSERT INTO screen_share_requests (student_id) VALUES (?)", (current_user.id,))
    conn.commit()
    conn.close()
    flash("Screen-sharing request submitted.")
    return redirect(url_for('dashboard'))

# Run the Flask app
if __name__ == '__main__':
    socketio.run(app, debug=True)
