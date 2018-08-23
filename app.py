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
from werkzeug.utils import secure_filename
import os
import uuid

UPLOAD_FOLDER = '/static/images'
# only allow images to be uploaded
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
db = SQLAlchemy(app)

app.config.update(dict(
	SECRET_KEY="powerful secretkey",
	WTF_CSRF_SECRET_KEY="a csrf secret key"
))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/evo_lution.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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
	owner = db.Column(db.Integer, db.ForeignKey("user.id"))
	breed = db.Column(db.Integer, db.ForeignKey("breed.id"))
	picture = db.Column(db.String(32))

	ownerR = db.relationship('User', foreign_keys=[owner])
	breedR = db.relationship('Breed', foreign_keys=[breed])

	def __init__(self, name, owner, breed, picture):
		self.name = name
		self.owner = owner
		self.breed = breed
		self.picture = picture

class Breed(db.Model):
	__tablename__ = 'breed'
	id = db.Column(db.Integer, primary_key = True)
	bName = db.Column(db.String(32))

	def __init__(self, name):
		self.bName = name

class Genes(db.Model):
	__tablename__ = 'genes'
	id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.String(32))
	breed = db.Column(db.Integer, db.ForeignKey("breed.id"))

	breedR = db.relationship('Breed', foreign_keys=[breed])

	def __init__(self, name, breed):
		self.name = name
		self.breed = breed

class Attributes(db.Model):
	__tablename__ = 'attributes'
	id = db.Column(db.Integer, primary_key = True)
	animal = db.Column(db.Integer)
	gene = db.Column(db.Integer)

	def __init__(self, animal, gene):
		self.animal = animal
		self.gene = gene

class LoginForm(Form):
	username = TextField('Username', [validators.Required()])
	password = PasswordField('Password', [validators.Required()])
	submit = SubmitField('Submit')

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)
		self.user = None

	def validate(self):
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
	username = TextField('Username', validators=[validators.Required()])
	email = TextField('E-Mail', validators=[validators.Required(), validators.Email()])
	password = PasswordField('New Password', [
		validators.DataRequired(),
		validators.EqualTo('confirm', message='Passwords must match')
	])
	confirm = PasswordField('Repeat Password')
	firstname = TextField('First Name', validators=[validators.Required(), validators.Length(min=8, max=32, message="Password must be between 8 and 32 characters long")])
	lastname = TextField('Last Name', validators=[validators.Required()])
	submit = SubmitField('Submit')

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)

	def validate(self):
		if self.username.data and self.password.data and self.confirm.data:
			if User.query.filter_by(username=self.username.data).first():
				flash('An account with that username already exists.', category='danger')
				return False
			if User.query.filter_by(email=self.email.data).first():
				flash('An account with that email already exists.', category='danger')
				return False
			return True
		return False

class AddNewForm(Form):
	name = TextField('Name', [validators.Required()])
	breed = SelectField('Breed', validators=[validators.Required()], id='select_breed')
	genes = SelectField('Genes', validators=[validators.Required()], id='select_genes')
	picture = FileField('Image', validators=[validators.Required()])
	submit = SubmitField('Submit')

	def __init__(self, *args, **kwargs):
		Form.__init__(self, *args, **kwargs)

	def validate(self):
		if self.name.data and self.breed.data and self.genes.data and self.picture.data:
			print(request.files)
			if 'picture' not in request.files:
				flash("No file part")
				return False
			self.pictureFile = request.files['picture']
			# if user does not select file, browser also
			# submit a empty part without filename
			if self.pictureFile.filename == '':
				flash('No selected file')
			elif self.pictureFile and allowed_file(self.pictureFile.filename):
				return True
			else:
				flash('Image must be in png, jpg, jpeg, or gif.')
		return False

@app.route('/_get_genes/')
def _get_genes():
	breed = request.args.get('breed', 1, type=int)
	genes = [(row.id, row.name) for row in Genes.query.filter_by(breed=breed).all()]
	return jsonify(genes)

@app.route('/')
def home():
	return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
	#print(request.cookies.get('evo_lution_session'))
	user_id = current_user.get_id()
	#animals = Animal.query.join(Breed).filter_by(owner=user_id).all()
	animals = e.execute("""select * from animal inner join breed on animal.breed=breed.id where animal.owner=""" + str(user_id) + """;""")
	return render_template('index.html', data=animals)

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		if form.validate():
			flash("You're now logged in!", category='success')
			return redirect('/dashboard')
		else:
			flash("No user with that email/password combo", category='danger')
	return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
	form = RegisterForm()
	if form.validate_on_submit():
		if form.validate():
			user = User(form.username.data, form.firstname.data, form.lastname.data, form.email.data, form.password.data)
			db.session.add(user)
			db.session.commit()
			flash("You're now registered!", category='success')
			return redirect('/login')
		else:
			flash("Error: Check your inputs", category='danger')
	return render_template('register.html', form=form)


@app.route("/logout")
@login_required
def logout():
	logout_user()
	return redirect('/')


@app.route("/addition", methods=['GET', 'POST'])
@login_required
def addition():
	form = AddNewForm()
	form.breed.choices = [(g.id, g.name) for g in Breed.query.all()]
	form.genes.choices = [(g.id, g.name) for g in Genes.query.all()]

	if form.validate_on_submit():
		print("validated on submit")
		if form.validate():
			file = form.picture.data
			uuidname = str(uuid.uuid1()) + secure_filename(file.filename)
			filename = (os.path.join(app.config['UPLOAD_FOLDER'], uuidname))
			file.save('.' + filename)

			breed = dict(form.breed.choices).get(int(form.breed.data))
			genes = dict(form.genes.choices).get(int(form.genes.data))
			
			animal = Animal(form.name.data, current_user.get_id(), breed, filename)
			db.session.add(animal)
			db.session.flush()
			# for g in form.genes.data:
			# 	gene = Genes(animal.id, g.value, 2)
			# 	db.session.add(gene)
			gene = Attributes(animal.id, Genes.query.filter_by(name=genes).first().id)
			db.session.add(gene)
			db.session.commit()
			flash("New Animal Added!", category='success')
			return redirect('/dashboard')
		else:
			print("here we are")
			flash("Error: Check your inputs", category='danger')
	return render_template('addition.html', form=form)

@login_manager.unauthorized_handler
def unauthorized_callback():
	return redirect('/login')


login_manager.init_app(app)

manager = APIManager(app, flask_sqlalchemy_db=db)
manager.create_api(User, methods=['GET'],results_per_page=10)

if __name__ == "__main__":
	app.run(host="0.0.0.0", debug=True)
	#app.run(host='0.0.0.0', port=80)
