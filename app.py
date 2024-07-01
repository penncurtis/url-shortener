from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import random
import string

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://penncu:your_password@localhost/url_shortener_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    urls = db.relationship('URLMapping', backref='user', lazy=True)

class URLMapping(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    short_url = db.Column(db.String(6), unique=True, nullable=False)
    long_url = db.Column(db.String(2048), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_short_url():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

@app.route('/')
def home():
    user_urls = URLMapping.query.filter_by(user_id=current_user.id).all() if current_user.is_authenticated else []
    return render_template('index.html', urls=user_urls)

@app.route('/dashboard')
@login_required
def dashboard():
    user_urls = URLMapping.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', urls=user_urls)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/shorten', methods=['POST'])
def shorten_url():
    long_url = request.form['long_url']
    custom_alias = request.form.get('custom_alias')

    if custom_alias:
        if not current_user.is_authenticated:
            flash('You need to be logged in to create a custom alias.', 'danger')
            return redirect(url_for('home'))
        
        short_url = custom_alias
        if URLMapping.query.filter_by(short_url=short_url).first():
            return render_template('index.html', error="Custom alias already exists.")
    else:
        short_url = generate_short_url()

    user_id = current_user.id if current_user.is_authenticated else None
    new_mapping = URLMapping(short_url=short_url, long_url=long_url, user_id=user_id)
    db.session.add(new_mapping)
    db.session.commit()

    full_short_url = request.host_url + short_url
    return render_template('index.html', short_url=full_short_url)

@app.route('/<short_url>')
def redirect_url(short_url):
    url_mapping = URLMapping.query.filter_by(short_url=short_url).first()
    if url_mapping:
        return redirect(url_mapping.long_url)
    else:
        return '<h1>URL not found</h1>'

@app.route('/delete/<int:url_id>', methods=['POST'])
@login_required
def delete_url(url_id):
    url_mapping = URLMapping.query.get_or_404(url_id)
    if url_mapping.user_id != current_user.id:
        flash('You are not authorized to delete this URL', 'danger')
        return redirect(url_for('home'))
    
    db.session.delete(url_mapping)
    db.session.commit()
    flash('URL deleted successfully', 'success')
    return redirect(url_for('home'))

@app.route('/edit/<int:url_id>', methods=['GET', 'POST'])
@login_required
def edit_url(url_id):
    url_mapping = URLMapping.query.get_or_404(url_id)
    if url_mapping.user_id != current_user.id:
        flash('You are not authorized to edit this URL', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        url_mapping.long_url = request.form['long_url']
        db.session.commit()
        flash('URL updated successfully', 'success')
        return redirect(url_for('home'))
    
    return render_template('edit_url.html', url=url_mapping)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)