from datetime import datetime
import os
from functools import wraps
from flask import Flask, request, jsonify, make_response, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from typing import Optional
from sqlalchemy.exc import SQLAlchemyError

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
	user_id = db.Column(db.BigInteger, db.ForeignKey('users.id'), nullable=False)
	subject = db.Column(db.BigInteger, db.ForeignKey('subjects.id'), nullable=False)
	body = db.Column(db.Text, nullable=False)
	channel = db.Column(db.BigInteger, db.ForeignKey('channels.id'), nullable=False)
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
	res_detail: str
	if request.method == 'GET':
		user_id: Optional[int] = request.args.get('user_id', default=None, type=int)
		subject_id: Optional[int] = request.args.get('subject_id', default=None, type=int)
		if user_id:
			user_ls: list[Users] = Users.query.filter_by(id=user_id).all()
			if user_ls:
				if not user_ls[0].is_banned:
					posts_from_db: list[Posts] = Posts.query.filter_by(user_id=user_id).all()
					posts: list[dict] = [post.get_dict() for post in posts_from_db]
					return make_response(jsonify(posts), 200)
				else:
					res_detail = 'user is banned'
					return make_response(jsonify({'task': 'get posts', 'status': 'failed', 'detail': res_detail}), 403)
			res_detail = 'user does not exist'
			return make_response(jsonify({'task': 'get posts', 'status': 'failed', 'detail': res_detail}), 404)
		elif subject_id:
			posts_from_db: list[Posts] = Posts.query.filter_by(subject=subject_id)
			posts: list[dict] = [post.get_dict() for post in posts_from_db if not post.user.is_banned]
			return make_response(jsonify(posts), 200)
		else:
			posts_from_db: list[Posts] = Posts.query.all()
			posts: list[dict] = [post.get_dict() for post in posts_from_db if not post.user.is_banned]
			return make_response(jsonify(posts), 200)
	else:
		try:
			post_data: dict = request.json
			post: Posts = Posts(user_id=session['user']['id'],
								subject=(post_data.get('subject')),
								channel=(post_data.get('channel')),
								body=(post_data.get('body')))
			db.session.add(post)
			db.session.commit()
			return make_response(jsonify({'task': 'post_message', 'status': 'success'}), 200)
		except SQLAlchemyError as e:
			return make_response(jsonify({'task': 'post_message', 'status': 'failed', 'detail': str(e)}), 400)


@app.route('/posts/<int:id_>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def post_by_id(id_: int):
	"""
	get message by id
	update message by id (if the user is the poster)
	delete message by id (if the user is the poster)
	"""
	res_detail: str
	posts_by_id: list[Posts] = Posts.query.filter_by(id=id_).all()
	if posts_by_id:
		if request.method == 'GET':
			posts: list[dict] = [post.get_dict() for post in posts_by_id]
			return make_response(jsonify(posts), 200)
		elif request.method == 'PUT':
			try:
				req_body: dict = request.json
				posts_by_id[0].subject = req_body['subject']
				posts_by_id[0].channel = req_body['channel']
				posts_by_id[0].body = req_body['body']
				posts_by_id[0].time_updated = datetime.utcnow()
				db.session.commit()
				return make_response(jsonify({'task': 'update_post', 'status': 'success'}), 200)
			except SQLAlchemyError as e:
				return make_response(jsonify({'task': 'update_post', 'status': 'failed', 'detail': str(e)}), 400)
		else:
			db.session.delete(posts_by_id[0])
			db.session.commit()
			return make_response(jsonify({'task': 'delete_post', 'status': 'success'}), 200)
	res_detail = 'post does not exist'
	return make_response(jsonify({'task': 'get_post_by_id', 'status': 'failed', 'detail': res_detail}), 404)


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
