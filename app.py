from flask_login import LoginManager, login_user, current_user, login_required, logout_user, UserMixin
from flask import Flask,jsonify,request,render_template,Response,flash,redirect,url_for
from flask_restless import APIManager
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_wtf import Form
from wtforms import TextField, BooleanField, validators, PasswordField, SubmitField
from werkzeug.security import generate_password_hash, \
	 check_password_hash
import datetime
from sqlalchemy import create_engine
#from wtforms.validators import Required

app = Flask(__name__)
db = SQLAlchemy(app)

app.config.update(dict(
	SECRET_KEY="powerful secretkey",
	WTF_CSRF_SECRET_KEY="a csrf secret key"
))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/evo_lution.db'

e = create_engine('sqlite:///database/evo_lution.db')

login_manager = LoginManager()


@login_manager.user_loader
def get_user(ident):
  return User.query.get(int(ident))

class User(db.Model, UserMixin):
	__tablename__ = 'user'
	id = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.String(32))
	email = db.Column(db.String(32))
	password = db.Column(db.String(32))

	def __init__(self, username, email, password):
		self.username = username
		self.set_password(password)
		self.email = email

	def set_password(self, password):
		self.pw_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password, password)
		#return password == self.password

class LoginForm(Form):
	username = TextField('Username', [validators.Required()])
	password = PasswordField('Password', [validators.Required()])
	submit = SubmitField('Submit')

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)
		self.user = None

	def validate(self):
		rv = Form.validate(self)
		if not rv:
			return False

		user = User.query.filter_by(
			username=self.username.data).first()
		if user is None:
			self.username.errors.append('Unknown username')
			return False

		if not user.check_password(self.password.data):
			self.password.errors.append('Invalid password')
			return False

		self.user = user
		login_user(user)
		return True

class RegisterForm(Form):
	username = TextField('Username', [validators.Required()])
	email = TextField('E-Mail', [validators.Required()])
	password = PasswordField('Password', [validators.Required()])
	passwordCopy = PasswordField('Re-Enter Password', [validators.Required()])
	submit = SubmitField('Submit')

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)
		self.user = None

	def validate_and_insert(self):
		rv = Form.validate(self)
		if not rv:
			return False
		if self.username.data and self.password.data and self.passwordCopy.data:
			if self.password.data == self.passwordCopy.data:
				user = User(self.username.data, self.email.data, self.password.data)
				self.insert(user.username, user.email, user.pw_hash)
				return True
			return False
		return False

	def insert(self, username, email, password):
		id = e.execute("""insert into user (username, password, email, is_active) values (:Username, :Password, :Email, '1');""",
			Username=username, Email=email, Password=password
			)
		return id

@app.route('/')
#@login_required
def home():
	return render_template('home.html')

@app.route('/dashboard')
def dashboard():
	#print(request.cookies.get('evo_lution_session'))
	return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		if form.validate():
			flash("You're now logged in!", category='success')
			return redirect('/dashboard')
		else:
			flash("No user with that email/password combo", category='failure')
	return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
	form = RegisterForm()
	if form.validate_on_submit():
		if form.validate_and_insert():
			flash("You're now registered!", category='success')
			return redirect('/login')
		else:
			flash("Error: Check your inputs", category='failure')
	return render_template('register.html', form=form)


@app.route("/logout")
# @login_required
def logout():
	logout_user()
	return redirect('/')


login_manager.init_app(app)

manager = APIManager(app, flask_sqlalchemy_db=db)
manager.create_api(User, methods=['GET'],results_per_page=10)

if __name__ == "__main__":
	app.run(host="0.0.0.0", debug=True)
