from datetime import datetime
import os
from functools import wraps
from flask import Flask, request, jsonify, make_response, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from typing import Optional

from utils.auth import signup_pw_validation

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ['SQLALCHEMY_DATABASE_URI']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.environ['SQLALCHEMY_TRACK_MODIFICATIONS'] == 'True'

CORS(app)

db = SQLAlchemy(app)


class Users(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.BigInteger, primary_key=True)
	username = db.Column(db.Text, unique=True, nullable=False)
	password = db.Column(db.Text, nullable=False)
	is_admin = db.Column(db.Boolean, nullable=False)
	is_banned = db.Column(db.Boolean, nullable=False)

	def get_dict(self):
		return {
			'id': self.id,
			'username': self.username,
			'password': self.password,
			'is_admin': self.is_admin,
			'is_banned': self.is_banned
		}


class Subjects(db.Model):
	__tablename__ = 'subjects'
	id = db.Column(db.BigInteger, primary_key=True)
	subject = db.Column(db.Text, unique=True, nullable=False)


class Channels(db.Model):
	__tablename__ = 'channels'
	id = db.Column(db.BigInteger, primary_key=True)
	channel = db.Column(db.Text, unique=True, nullable=False)


class Posts(db.Model):
	__tablename__ = 'posts'
	id = db.Column(db.BigInteger, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	subject = db.Column(db.Integer, db.ForeignKey('subjects.id'), nullable=False)
	body = db.Column(db.Text, nullable=False)
	channel = db.Column(db.Integer, db.ForeignKey('channels.id'), nullable=False)
	time_crated = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
	time_updated = db.Column(db.DateTime, nullable=True, default=None)
	user = db.relationship("Users", backref="users")

	def get_dict(self):
		return {
			'id': self.id,
			'user_id': self.user_id,
			'subject': self.subject,
			'body': self.body,
			'channel': self.channel,
			'time_crated': self.time_crated,
			'time_updated': self.time_updated
		}


def login_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		if 'user' in session:
			return f(*args, **kwargs)
		return make_response(jsonify({'task': 'failed', 'detail': 'unauthorized'}), 401)
	return decorated


def admin_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		if 'user' in session:
			if session['user']['is_admin']:
				return f(*args, **kwargs)
			return make_response(jsonify({'task': 'failed', 'detail': 'forbidden'}), 403)
		return make_response(jsonify({'task': 'failed', 'detail': 'unauthorized'}), 401)
	return decorated


@app.route("/signup", methods=['POST'])
def signup():
	password: str = request.form['password']
	username: str = request.form['username']
	if Users.query.filter_by(username=username).all():
		return make_response(jsonify({'task': 'signup', 'status': 'failed', 'reason': 'username already exists'}), 409)
	if not signup_pw_validation(password):
		return make_response(jsonify({'task': 'login', 'status': 'failed', 'reason': 'password must be more then 10 characters'}), 400)
	hashed_password = generate_password_hash(password, method='sha256')
	new_user: Users = Users(username=username, password=hashed_password, is_admin=False, is_banned=False)
	db.session.add(new_user)
	db.session.commit()
	return make_response(jsonify({'task': 'signup', 'status': 'success'}), 200)


@app.route('/login', methods=['POST'])
def login():
	password: str = request.form['password']
	username: str = request.form['username']
	# checking if the user and password are in the db
	user_ls: list[Users] = Users.query.filter_by(username=username).all()
	if user_ls and check_password_hash(user_ls[0].password, password):
		session['user'] = user_ls[0].get_dict()
		return make_response(jsonify({'task': 'login', 'status': 'success'}), 200)
	return make_response(jsonify({'task': 'login', 'status': 'failed'}), 401)


@app.route('/logout', methods=['POST'])
def logout():
	if 'user' in session:
		session.pop('user')
		return make_response(jsonify({'task': 'logout', 'status': 'success'}), 200)
	return make_response(jsonify({'task': 'logout', 'status': 'failed'}), 401)


@app.route('/posts', methods=['GET', 'POST'])
@login_required
def posts():
	"""
	post massage (if user is not banned)
	get all messages (that their poster is not banned)
	get message by subject (returns all public messages in the subject) - query params
	get posts by user_id (returns all public messages from the user)- query params
	"""


@app.route('/posts/<int:id_>', methods=['GET', 'PUT', 'DELETE'])
def post_by_id(id_: int):
	"""
	get message by id
	update message by id (if the user is the poster)
	delete message by id (if the user is the poster)
	"""
	...


@app.route('/users/<int:id_>', methods=['PUT'])
@admin_required
def user_by_id(id_: int):
	"""
	update is_banned (if the user is admin)
	"""
	user_to_update_ls: list[Users] = Users.query.filter_by(id=id_).all()
	if user_to_update_ls:
		req_body: dict[str, bool] = request.json
		if 'is_banned' in req_body and type(req_body['is_banned']) == bool:
			user_to_update_ls[0].is_banned = req_body['is_banned']
			db.session.commit()
			return make_response(jsonify({'task': 'update_user', 'status': 'success'}), 200)
		return make_response(jsonify({'task': 'update_user', 'status': 'failed', 'detail': 'request body is not valid'}), 400)
	return make_response(jsonify({'task': 'update_user', 'status': 'failed', 'detail': 'user id does not exist'}), 400)


if __name__ == '__main__':
	app.run(port=5001, debug=True)
