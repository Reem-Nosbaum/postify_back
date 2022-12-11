from flask import Flask, request, jsonify, make_response, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY'] # creating a session

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ['SQLALCHEMY_DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.environ['SQLALCHEMY_TRACK_MODIFICATIONS'] == 'True'

CORS(app)

db = SQLAlchemy(app)

class Users(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.Text, unique=True, nullable=False)
	password = db.Column(db.Text, nullable=False)
	is_admin = db.Column(db.Boolean, nullable=False)
	is_banned = db.Column(db.Boolean, nullable=False)
	is_typing = db.Column(db.Boolean, nullable=False)


class Subjects(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	subject = db.Column(db.Text, unique=True, nullable=False)


class Groups(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	groups = db.Column(db.Text, unique=True, nullable=False)


class Posts(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	user = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	subject = db.Column(db.Integer, db.ForeignKey('subjects.id'), nullable=False)
	body = db.Column(db.Text, nullable=False)
	group = db.Column(db.Integer, db.ForeignKey('groups.id'))
	time = db.Column(db.DateTime, nullable=False, default=datetime.now())



@app.route("/signup", methods=['POST'])
def signup():
	password: str = request.form['password']
	username: str = request.form['username']
	if not username or not password:
		return make_response(jsonify({'task': 'login', 'status': 'failed', 'reason': 'Username and password are required'}), 400)
	if Users.query.filter_by(username=username).all():
		return make_response(jsonify({'task': 'signup', 'status': 'failed', 'reason': 'username already exists'}), 409)
	if len(password) < 10:
		return make_response(jsonify({'task': 'login', 'status': 'failed', 'reason': 'password must be more then 10 characters'}), 400)
	hashed_password = generate_password_hash(password, method='sha256')
	new_user = Users(username=username, password=hashed_password, is_admin=False, is_banned=False, is_typing=False)
	db.session.add(new_user)  # adding the new user to the db
	db.session.commit()
	return make_response(jsonify({'task': 'signup', 'status': 'success'}), 200)


@app.route('/login', methods=['POST'])
def login():
	password: str = request.form['password']
	username: str = request.form['username']
	if not username or not password:
		return make_response(jsonify({'task': 'login', 'status': 'failed', 'reason': 'Username and password are required'}), 400)
	if len(password) < 10:
		return make_response(jsonify({'task': 'login', 'status': 'failed', 'reason': 'password must be more then 10 characters'}), 400)
	# checking if the user and password are in the db
	user_ls: list[Users] = Users.query.filter_by(username=username).all()
	if user_ls and check_password_hash(user_ls[0].password, password):
		session['username'] = True
		return make_response(jsonify({'task': 'login', 'status': 'success'}), 200)
	return make_response(jsonify({'task': 'login', 'status': 'failed'}), 401)


@app.route('/logout', methods=['POST'])
def logout():
	if 'username' in session:
		session.pop('username')
		return make_response(jsonify({'task': 'logout', 'status': 'success'}), 200)
	return make_response(jsonify({'task': 'logout', 'status': 'failed'}), 401)


@app.route('/posts', methods=['GET', 'POST'])
def posts():
	"""
	post massage (if user is not banned)
	get all messages (that their poster is not banned)
	get message by subject (returns all public messages in the subject) - query params
	get posts by user_id (returns all public messages from the user)- query params
	"""
	...


@app.route('/posts/<int:id_>', methods=['GET', 'PUT', 'DELETE'])
def post_by_id(id_):
	"""
	get message by id
	update message by id (if the user is the poster)
	delete message by id (if the user is the poster)
	"""
	...


@app.route('/users/<int:id_>', methods=['PUT'])
def user_by_id(id_):
	"""
	update is_banned (if the user is admin)
	"""
	...


if __name__ == '__main__':
	app.run(debug=True)
