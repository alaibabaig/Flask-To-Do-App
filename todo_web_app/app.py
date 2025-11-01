import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, BooleanField, DateTimeField
from wtforms.validators import DataRequired, Length, EqualTo, Email, Optional
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- Config ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_this_to_a_random_secret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------- Models ----------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    due_date = db.Column(db.DateTime, nullable=True)
    priority = db.Column(db.String(10), nullable=False, default='Medium')  # Low, Medium, High
    category = db.Column(db.String(100), nullable=True)
    reminder_at = db.Column(db.DateTime, nullable=True)
    tags = db.Column(db.String(300), nullable=True)  # comma separated

    is_completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ---------- Forms ----------
class SignupForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(1, 100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    description = TextAreaField('Description', validators=[Optional(), Length(max=2000)])
    due_date = StringField('Due Date (YYYY-MM-DD HH:MM) — optional', validators=[Optional()])
    priority = SelectField('Priority', choices=[('Low','Low'), ('Medium','Medium'), ('High','High')], default='Medium')
    category = StringField('Category (optional)', validators=[Optional(), Length(max=100)])
    reminder_at = StringField('Reminder (YYYY-MM-DD HH:MM) — optional', validators=[Optional()])
    tags = StringField('Tags (comma separated) — optional', validators=[Optional(), Length(max=300)])
    is_completed = BooleanField('Completed')
    submit = SubmitField('Save')

# ---------- Login loader ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------- Helpers ----------
def parse_datetime(s):
    """Try to parse datetime from 'YYYY-MM-DD HH:MM' or 'YYYY-MM-DD' or None."""
    if not s:
        return None
    s = s.strip()
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None

# ---------- Routes ----------
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data.lower()).first():
            flash('Email already registered. Please login.', 'warning')
            return redirect(url_for('login'))
        user = User(name=form.name.data, email=form.email.data.lower())
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created — please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Welcome back, {}'.format(user.name), 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Filtering params
    q_category = request.args.get('category', type=str)
    q_priority = request.args.get('priority', type=str)
    q_status = request.args.get('status', type=str)  # all, completed, pending
    q_sort = request.args.get('sort', 'due')  # due, created, priority

    tasks = Task.query.filter_by(user_id=current_user.id)

    if q_category:
        tasks = tasks.filter(Task.category.ilike(f"%{q_category}%"))
    if q_priority:
        tasks = tasks.filter_by(priority=q_priority)
    if q_status == 'completed':
        tasks = tasks.filter_by(is_completed=True)
    elif q_status == 'pending':
        tasks = tasks.filter_by(is_completed=False)

    if q_sort == 'due':
        tasks = tasks.order_by(Task.due_date.asc().nulls_last())
    elif q_sort == 'created':
        tasks = tasks.order_by(Task.created_at.desc())
    elif q_sort == 'priority':
        # custom ordering High, Medium, Low
        tasks = tasks.order_by(db.case(
            (Task.priority == 'High', 1),
            (Task.priority == 'Medium', 2),
            (Task.priority == 'Low', 3),
            else_=4
        ))

    tasks = tasks.all()
    return render_template('dashboard.html', tasks=tasks, filters={
        'category': q_category or '',
        'priority': q_priority or '',
        'status': q_status or 'all',
        'sort': q_sort or 'due'
    })

@app.route('/task/add', methods=['GET','POST'])
@login_required
def add_task():
    form = TaskForm()
    if form.validate_on_submit():
        due = parse_datetime(form.due_date.data)
        reminder = parse_datetime(form.reminder_at.data)
        t = Task(
            user_id=current_user.id,
            title=form.title.data,
            description=form.description.data,
            due_date=due,
            priority=form.priority.data,
            category=form.category.data or None,
            reminder_at=reminder,
            tags=form.tags.data,
            is_completed=bool(form.is_completed.data)
        )
        db.session.add(t)
        db.session.commit()
        flash('Task created.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_edit_task.html', form=form, action='Add Task')

@app.route('/task/<int:task_id>/edit', methods=['GET','POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    form = TaskForm()

    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        task.due_date = parse_datetime(form.due_date.data)
        task.priority = form.priority.data
        task.category = form.category.data or None
        task.reminder_at = parse_datetime(form.reminder_at.data)
        task.tags = form.tags.data
        task.is_completed = bool(form.is_completed.data)
        db.session.commit()
        flash('Task updated.', 'success')
        return redirect(url_for('dashboard'))

    # Pre-fill
    if request.method == 'GET':
        form.title.data = task.title
        form.description.data = task.description
        form.due_date.data = task.due_date.strftime("%Y-%m-%d %H:%M") if task.due_date else ''
        form.priority.data = task.priority
        form.category.data = task.category or ''
        form.reminder_at.data = task.reminder_at.strftime("%Y-%m-%d %H:%M") if task.reminder_at else ''
        form.tags.data = task.tags or ''
        form.is_completed.data = task.is_completed

    return render_template('add_edit_task.html', form=form, action='Edit Task')

@app.route('/task/<int:task_id>/delete', methods=['GET','POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    if request.method == 'POST':
        db.session.delete(task)
        db.session.commit()
        flash('Task deleted permanently.', 'info')
        return redirect(url_for('dashboard'))
    return render_template('confirm_delete.html', task=task)

@app.route('/task/<int:task_id>/toggle')
@login_required
def toggle_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        abort(403)
    task.is_completed = not task.is_completed
    db.session.commit()
    return redirect(url_for('dashboard'))

# ---------- CLI helper to init DB ----------
@app.cli.command('init-db')
def init_db():
    """Initialize the database (Flask CLI: flask init-db)"""
    db.create_all()
    print("DB initialized.")

# ---------- Create DB on first run ----------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)