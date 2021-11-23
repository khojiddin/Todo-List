from flask import render_template, redirect, request, abort, url_for, Flask, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import RegisterForm, LoginForm, CreateListForm, EditUserForm, EditUserPasswordForm
from datetime import datetime
from functools import wraps
from url_generator import generate_url
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
Bootstrap(app)

# SQLAlchemy CONNECTION
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL1', 'sqlite:///data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(100))

    lists = relationship('ToDoList', back_populates='user')
    todo = relationship('ToDo', back_populates='owner')


class ToDoList(db.Model):
    __tablename__ = 'todolist'
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship('User', back_populates='lists')

    url = db.Column(db.Integer, unique=True)
    name = db.Column(db.String(100))

    child = relationship('ToDo', back_populates='parent_list')


class ToDo(db.Model):
    __tablename__ = 'todos'

    id = db.Column(db.Integer, primary_key=True)

    parent_list_url = db.Column(db.Integer, db.ForeignKey('todolist.url'))
    parent_list = relationship('ToDoList', back_populates='child')

    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    owner = relationship('User', back_populates='todo')

    data = db.Column(db.String(250))
    date = db.Column(db.String(10))
    status = db.Column(db.Boolean)


class PublicList(db.Model):
    __tablename__ = 'public-list'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(250), unique=True)
    name = db.Column(db.String(250))

    ParentList = relationship('PublicToDo', back_populates='child')


class PublicToDo(db.Model):
    __tablename__ = 'public-todo'
    id = db.Column(db.Integer, primary_key=True)

    ListUrl = db.Column(db.String(250), db.ForeignKey('public-list.url'))
    child = relationship('PublicList', back_populates='ParentList')

    status = db.Column(db.Boolean)
    date = db.Column(db.String(10))
    data = db.Column(db.String(250))


db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decor_function(*args, **kwargs):
        if current_user.id != 1 or not current_user.is_authenticated:
            return abort(404)
        else:
            return f(*args, **kwargs)

    return decor_function


def unsigned_only(f):
    @wraps(f)
    def check(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id == 1:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('home'))

    return check


@app.route('/')
def home():
    new_list_form = CreateListForm()
    return render_template('homepage.html', listForm=new_list_form, logged_in=current_user.is_authenticated)


@app.route('/public_use', methods=['POST', 'GET'])
def public_use():

    list_url = request.args.get('list_url')
    todo_data = PublicToDo.query.filter_by(ListUrl=list_url).all()
    public_list = PublicList.query.filter_by(url=list_url).first()
    if request.method == 'POST':
        data = request.form['data']
        new_data = PublicToDo(ListUrl=list_url, data=data, status=False)
        db.session.add(new_data)
        db.session.commit()
        return redirect(url_for('public_use', list_url=new_data.ListUrl, logged_in=current_user.is_authenticated))

    return render_template('public-use.html', logged_in=current_user.is_authenticated, list=public_list
                           , todo_public=todo_data)


@app.route('/create-new-public-list')
def create_public_list():
    date_now = datetime.now().strftime('%x')
    url = generate_url()
    new_list = PublicList(name=f"New list {date_now}", url=url)
    db.session.add(new_list)
    db.session.commit()
    return redirect(url_for('public_use', list_url=new_list.url))


@app.route('/login', methods=['POST', 'GET'])
@unsigned_only
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                first_list = ToDoList.query.filter_by(user_id=current_user.id).first()
                return redirect(url_for('user_page', list_id=first_list.id))
            else:
                flash('Incorrect password!Try again!')
        else:
            flash('User with this email does not exist! Register instead')
            return redirect(url_for('register'))

    return render_template('login.html', form=form, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['POST', 'GET'])
@unsigned_only
def register():
    form = RegisterForm()
    login_form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        if User.query.filter_by(email=email).first():
            flash('User with this email already exist. Please Log in.')
            redirect(url_for('home'))
        else:
            name = form.name.data
            password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=12)
            new_user = User(email=email, name=name, password=password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            date_now = datetime.now().strftime('%x')
            url = generate_url()
            new_list = ToDoList(user_id=current_user.id, name=f"New list {date_now}", url=url)
            db.session.add(new_list)
            db.session.commit()

            return redirect(url_for('user_page', list_id=new_list.url))

    return render_template('register.html', form=form, login_form=login_form, logged_in=current_user.is_authenticated)


@app.route('/user', methods=['POST', 'GET'])
def user_page():
    if current_user.is_authenticated:
        new_list_form = CreateListForm()
        current_list = request.args.get('list_url')
        if not current_list:
            first_list = ToDoList.query.filter_by(user_id=current_user.id).first()
            if not first_list:
                date_now = datetime.now().strftime('%x')
                url = generate_url()
                new_list = ToDoList(user_id=current_user.id, name=f"New list {date_now}", url=url)
                db.session.add(new_list)
                db.session.commit()
                current_list = new_list.url
            else:
                current_list = first_list.url

        lists = ToDoList.query.filter_by(user_id=current_user.id).all()
        todo_list = ToDoList.query.filter_by(url=current_list).first()
        todo_data = ToDo.query.filter_by(parent_list_url=current_list, owner_id=current_user.id).all()

        if request.method == 'POST':

            if new_list_form.validate_on_submit():
                url = generate_url()
                new_list = ToDoList(name=new_list_form.name.data, user_id=current_user.id, url=url)
                db.session.add(new_list)
                db.session.commit()
                return redirect(url_for('user_page', logged_in=current_user.is_authenticated, list_url=new_list.url))
            else:
                data = request.form['data']
                new_data = ToDo(parent_list_url=current_list, owner_id=current_user.id, data=data, status=False)
                db.session.add(new_data)
                db.session.commit()
                return redirect(url_for('user_page', logged_in=current_user.is_authenticated, list_url=new_data.parent_list_url))

        return render_template('user_page.html', current_user=current_user,
                               logged_in=current_user.is_authenticated,
                               listForm=new_list_form,
                               todo_lists=lists,
                               todo_data=todo_data,
                               current_list=todo_list)
    else:
        current_list = request.args.get('list_url')
        if current_list:
            todo_list = ToDoList.query.filter_by(url=current_list).first()
            todo_data = ToDo.query.filter_by(parent_list_url=current_list).all()
            return render_template('shared_page.html', shared_data=todo_data, logged_in=current_user.is_authenticated, current_list=todo_list)
        return redirect(url_for('home'))


@app.route('/logout')
@login_required
def log_out():
    logout_user()
    return redirect(url_for('home'))


@app.route('/remove-task', methods=['POST', 'GET'])
def remove_task():
    list_url = request.args.get('list_url')
    task_id = request.args.get('current_task_id')
    delete_task = ToDo.query.filter_by(parent_list_url=list_url, id=task_id).first()
    if delete_task:
        db.session.delete(delete_task)
        db.session.commit()
        return redirect(url_for('user_page', list_url=list_url))
    else:
        delete_public_task = PublicToDo.query.filter_by(ListUrl=list_url, id=task_id).first()
        if delete_public_task:
            db.session.delete(delete_public_task)
            db.session.commit()
            return redirect(url_for('public_use', list_url=list_url))


@app.route('/update-status', methods=['POST'])
def update_status():
    task_id = request.args.get('current_task_id')
    list_url = request.args.get('list_url')
    task = ToDo.query.filter_by(parent_list_url=list_url, id=task_id).first()
    if task:
        if task.status:
            task.status = False
        else:
            task.status = True
        db.session.commit()
        return redirect(url_for('user_page', list_url=task.parent_list_url))
    else:
        public_task = PublicToDo.query.filter_by(ListUrl=list_url, id=task_id).first()
        if public_task.status:
            public_task.status = False
        else:
            public_task.status = True
        db.session.commit()
        return redirect(url_for('public_use', list_url=public_task.ListUrl))


@app.route('/user-settings', methods=['POST', 'GET'])
@login_required
def user_config():
    passwordForm = EditUserPasswordForm()
    form = EditUserForm(name=current_user.name, email=current_user.email)

    if form.validate_on_submit():
        user = User.query.get(current_user.id)
        user.email = form.email.data
        user.name = form.name.data
        db.session.commit()
        return redirect(url_for('user_config'))

    all_lists = ToDoList.query.filter_by(user_id=current_user.id).all()
    return render_template('user-settings.html', password_form=passwordForm,
                           lists=all_lists, form=form, logged_in=current_user.is_authenticated)


@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    passwordForm = EditUserPasswordForm()

    if passwordForm.validate_on_submit():
        user = User.query.get(current_user.id)
        if check_password_hash(current_user.password, passwordForm.old_password.data):

            if passwordForm.new_password.data == passwordForm.confirm_password.data:
                new_password = generate_password_hash(passwordForm.new_password.data,
                                                      method="pbkdf2:sha256", salt_length=12)
                user.password = new_password
                db.session.commit()
                return redirect(url_for('user_config'))
            else:
                flash('could now match new password!')
                return redirect(url_for('user_config'))
        else:
            flash('Incorrect! old password!')
            return redirect(url_for('user_config'))


@app.route('/delete-list')
@login_required
def delete_list():
    list_url = request.args.get('list_url')
    list_to_delete = ToDoList.query.filter_by(url=list_url, user_id=current_user.id).first()
    pb_list_to_delete = PublicList.query.filter_by(url=list_url).first()
    if list_to_delete:
        list_data = ToDo.query.filter_by(parent_list_url=list_url, owner_id=current_user.id).all()
        for task in list_data:
            db.session.delete(task)
            db.session.commit()
        db.session.delete(list_to_delete)
        db.session.commit()
        return redirect(url_for('user_config'))
    if pb_list_to_delete:
        pb_list_data = PublicToDo.query.filter_by(ListUrl=list_url).all()
        for task in pb_list_data:
            db.session.delete(task)
            db.session.commit()
        db.session.delete(pb_list_to_delete)
        db.session.commit()
        return redirect(url_for('security'))
    else:
        return redirect(url_for('home'))


@app.route('/security-control')
@admin_only
def security():
    users = User.query.all()
    pb_l = PublicList.query.all()
    return render_template('users.html', logged_in=current_user.is_authenticated, users=users, pb_l=pb_l)


@app.route('/remove-bad-users')
@admin_only
def remove_bad_user():
    user_id = request.args.get('user_id')
    if user_id != 1:
        bad_user = User.query.filter_by(id=user_id).first()
        bad_user_lists = ToDoList.query.filter_by(user_id=user_id).all()
        if bad_user_lists:
            for list in bad_user_lists:
                bad_user_tasks = ToDo.query.filter_by(parent_list_url=list.url, owner_id=user_id).all()
                if bad_user_tasks:
                    for task in bad_user_tasks:
                        db.session.delete(task)
                db.session.delete(list)
        db.session.delete(bad_user)
        db.session.commit()
        return redirect(url_for('security'))


if __name__ == "__main__":
    app.run(debug=True)
