# app.py

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.csrf import CSRFError
from authlib.integrations.flask_client import OAuth
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import sqlite3
import zipfile
from io import BytesIO
#import os
#print(os.urandom(24))  # Generates a secure random key

app = Flask(__name__)
app.secret_key = ':\xa6\xfb\xd4;J\xa3J\x0b\xa5u#\xad#\xb9h\xc6^\xfd%\xbd+\x88\xbe'  # Replace with your actual secret key

csrf = CSRFProtect(app)  # Initialize CSRF protection

# Initialize OAuth
oauth = OAuth(app)

# Configure Google OAuth
google = oauth.register(
    name='google',
    client_id='Y865979457953-q98vp5btfrph48lbkb0ba1jo586t152q.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid profile email'}
)

# Configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'xlsx', 'pptx'])  # All file types

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    with conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
    conn.close()

# Initialize the database when the app starts
init_db()

class User(UserMixin):
    def __init__(self, id_, username, password):
        self.id = id_
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(id_=user['id'], username=user['username'], password=user['password'])
    return None

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Error handler for CSRF errors
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('The form session has expired. Please try again.', 'danger')
    return redirect(request.url)

# Routes for Google OAuth
@app.route('/login/google')
def google_login():
    redirect_uri = url_for('google_auth', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google')
def google_auth():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    username = user_info['email']

    # Check if user exists in DB, else create user
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user:
        # Create new user with a random password
        password = generate_password_hash(os.urandom(16).hex())
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    user_obj = User(id_=user['id'], username=user['username'], password=user['password'])
    login_user(user_obj)

    flash('Logged in successfully using Google.', 'success')
    return redirect(url_for('rename_tool'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()  # Instantiate the form
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)

        conn = get_db_connection()
        try:
            with conn:
                conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'danger')
        finally:
            conn.close()
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (form.username.data,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], form.password.data):
            user_obj = User(id_=user['id'], username=user['username'], password=user['password'])
            login_user(user_obj)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('rename_tool'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    login_form = LoginForm()
    registration_form = RegistrationForm()
    return render_template('index.html', login_form=login_form, registration_form=registration_form)

@app.route('/rename_tool', methods=['GET', 'POST'])
@login_required
def rename_tool():
    if request.method == 'POST':
        rename_pattern = request.form['rename_pattern']
        files = request.files.getlist('files')

        if not files or not rename_pattern:
            flash('No files or rename pattern provided.', 'danger')
            return redirect(url_for('rename_tool'))

        saved_files = []
        for index, file in enumerate(files, start=1):
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_ext = os.path.splitext(filename)[1]
                new_filename = f"{rename_pattern}_{index}{file_ext}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                file.save(file_path)
                saved_files.append(file_path)
            else:
                flash(f'File type not allowed or empty filename: {file.filename}', 'danger')

        if not saved_files:
            flash('No files were processed.', 'danger')
            return redirect(url_for('rename_tool'))

        # Create a ZIP file in memory
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w') as zf:
            for file_path in saved_files:
                zf.write(file_path, arcname=os.path.basename(file_path))
        memory_file.seek(0)

        # Clean up the uploaded files
        for file_path in saved_files:
            os.remove(file_path)

        flash('Your files have been renamed and are ready for download.', 'success')

        return send_file(
            memory_file,
            mimetype='application/zip',
            download_name='renamed_files.zip',
            as_attachment=True
        )

    return render_template('rename_tool.html')

if __name__ == '__main__':
    app.run(debug=True)
