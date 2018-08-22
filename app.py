from flask_login import LoginManager, login_user, current_user, login_required, logout_user, UserMixin
from flask import Flask,jsonify,request,render_template,Response,flash,redirect,url_for
from flask_restless import APIManager
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_wtf import Form
from wtforms import TextField, BooleanField, validators, PasswordField, SubmitField, SelectField, FileField
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
	firstname = db.Column(db.String(32))
	lastname = db.Column(db.String(32))
	email = db.Column(db.String(32))
	password = db.Column(db.String(32))

	def __init__(self, username, firstname, lastname, email, password):
		self.username = username
		self.set_password(password)
		self.email = email
		self.firstname = firstname
		self.lastname = lastname

	def set_password(self, password):
		self.pw_hash = generate_password_hash(password)

	def check_password(self, password):
		return check_password_hash(self.password, password)
		#return password == self.password

class Animal(db.Model):
	__tablename__ = 'animal'
	id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.String(32))
	owner = db.Column(db.Integer)
	breed = db.Column(db.Integer)
	picture = db.Column(db.String(32))

	def __init__(self, name, owner, breed, picture):
		self.name = name
		self.owner = owner
		self.email = email
		self.breed = breed
		self.picture = picture

class Breed(db.Model):
	__tablename__ = 'breed'
	id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.String(32))

	def __init__(self, name):
		self.name = name

class Genes(db.Model):
	__tablename__ = 'genes'
	id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.String(32))
	breed = db.Column(db.Integer)

	def __init__(self, name, breed):
		self.name = name
		self.breed = breed

class Attributes(db.Model):
	__tablename__ = 'attributes'
	id = db.Column(db.Integer, primary_key = True)
	animal = db.Column(db.Integer)
	gene = db.Column(db.Integer)
	dominance = db.Column(db.Integer)

	def __init__(self, animal, gene, dominance):
		self.animal = animal
		self.gene = gene
		self.dominance = dominance

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
	firstname = TextField('First Name', [validators.Required()])
	lastname = TextField('Last Name', [validators.Required()])
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
				user = User(self.username.data, self.firstname.data, self.lastname.data, self.email.data, self.password.data)
				self.insert(user.username, user.firstname, user.lastname, user.email, user.pw_hash)
				return True
			return False
		return False

	def insert(self, username, firstname, lastname, email, password):
		id = e.execute("""insert into user (username, firstname, lastname, password, email, is_active) values (:Username, :FirstName, :LastName, :Password, :Email, '1');""",
			Username=username, FirstName=firstname, LastName=lastname, Email=email, Password=password
			)
		return id

class AddNewForm(Form):
	name = TextField('Name', [validators.Required()])
	breed = SelectField('Breed', validators=[validators.Required()], id='select_breed')
	genes = SelectField('Genes', validators=[validators.Required()], id='select_genes')
	picture = FileField('Image', [validators.Required()])
	submit = SubmitField('Submit')

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)
		self.animal = None

	def validate_and_insert(self):
		
		pass

@app.route('/_get_genes/')
def _get_genes():
    breed = request.args.get('breed', 1, type=int)
    genes = [(row.id, row.name) for row in Genes.query.filter_by(breed=breed).all()]
    return jsonify(genes)

@app.route('/')
#@login_required
def home():
	return render_template('home.html')

@app.route('/dashboard')
def dashboard():
	#print(request.cookies.get('evo_lution_session'))
	user_id = current_user.get_id()
	animals = Animal.query.filter_by(owner=user_id).all()
	print(animals)
	for a in animals:
		print(a.name)
	return render_template('index.html', data=animals)

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


@app.route("/addition")
def addition():
	form = AddNewForm()
	form.breed.choices = [(g.id, g.name) for g in Breed.query.all()]
	form.genes.choices = [(g.id, g.name) for g in Genes.query.all()]
	if form.validate_on_submit():
		flash("New Animal Added!", category='success')
		return redirect('/addition')
	else:
		flash("Error: Check your inputs", category='failure')
	return render_template('addition.html', form=form)


login_manager.init_app(app)

manager = APIManager(app, flask_sqlalchemy_db=db)
manager.create_api(User, methods=['GET'],results_per_page=10)

if __name__ == "__main__":
	app.run(host="0.0.0.0", debug=True)
	#app.run(host='0.0.0.0', port=80)
