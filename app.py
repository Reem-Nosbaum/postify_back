from flask import Flask, request, jsonify, make_response, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from utils.auth import signup_pw_validation

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']

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

	def get_dict_user(self):
		return {'id': self.id, 'username': self.username, 'password': self.password, 'is_admin': self.is_admin, 'is_banned': self.is_banned}


class Subjects(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	subject = db.Column(db.Text, unique=True, nullable=False)


class Groups(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	group = db.Column(db.Text, unique=True, nullable=False)


class Posts(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	user = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
	subject = db.Column(db.Integer, db.ForeignKey('subjects.id'), nullable=False)
	body = db.Column(db.Text, nullable=False)
	group = db.Column(db.Integer, db.ForeignKey('groups.id'))
	time = db.Column(db.DateTime, nullable=False, default=datetime.now())

	def get_dict_post(self):
		return {'id': self.id, 'user': self.user, 'subject': self.subject, 'body': self.body, 'group': self.group, 'time': self.time}


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
		session['user'] = username
		session['is_admin'] = user_ls[0].is_admin
		session['is_banned'] = user_ls[0].is_banned
		return make_response(jsonify({'task': 'login', 'status': 'success'}), 200)
	return make_response(jsonify({'task': 'login', 'status': 'failed'}), 401)


@app.route('/logout', methods=['POST'])
def logout():
	if 'user' in session:
		session.pop('user')
		session.pop('is_admin')
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
	if not session['is_banned']:  # checking if the user is banned
		if request.method == 'GET':
			if 'subject' in request.args:
				get_all_posts_by_subject = Posts.query.filter_by(subject=request.args.get('subject'))
				all_dict_posts = [post.get_dict_post() for post in get_all_posts_by_subject]
			elif 'user' in request.args:
				get_all_posts_by_user_id = Posts.query.filter_by(user=request.args.get('user'))
				all_dict_posts = [post.get_dict_post() for post in get_all_posts_by_user_id]
			else:
				get_all_posts = Posts.query.filter_by(user=session['user']).all()
				all_dict_posts = [post.get_dict_post() for post in get_all_posts]
			return make_response(jsonify(all_dict_posts), 200)
		elif request.method == 'POST':
			subject = request.form['subject']
			body = request.form['body']
			group = request.form['group']
			new_post = Posts(user=session['user'], subject=subject, body=body, group=group)
			db.session.add(new_post)
			db.session.commit()
			return make_response(jsonify({'task': 'post', 'status': 'success'}), 200)
		return make_response(jsonify({'task': 'post', 'status': 'failed'}), 401)
	return make_response(jsonify({'task': 'post', 'status': 'failed', 'reason': 'user is banned'}), 403)


@app.route('/posts/<int:id_>', methods=['GET', 'PUT', 'DELETE'])
def post_by_id(id_: int):
	"""
	get message by id
	update message by id (if the user is the poster)
	delete message by id (if the user is the poster)
	"""
	if not session['is_banned']:
		if request.method == 'GET':
			get_posts_by_id: list[Posts] = Posts.query.filter_by(id=id_).all()
			all_dict_posts_by_id: list[dict] = [post.get_dict_post() for post in get_posts_by_id]
			return make_response(jsonify(all_dict_posts_by_id), 200)
		elif request.method == 'PUT':
			posts_by_id: list[Posts] = Posts.query.filter_by(id=id_).all()
			if session['user'] == posts_by_id[0].user:
				posts_by_id[0].body = request.form['body']
				db.session.commit()
				return make_response(jsonify({'task': 'put', 'status': 'success'}), 200)
			return make_response(jsonify({'task': 'put', 'status': 'failed'}), 401)
		elif request.method == 'DELETE':
			posts_by_id: list[Posts] = Posts.query.filter_by(id=id_).all()
			if session['user'] == posts_by_id[0].user:
				db.session.delete(posts_by_id[0])
				db.session.commit()
				return make_response(jsonify({'task': 'delete', 'status': 'success'}), 200)
			return make_response(jsonify({'task': 'delete', 'status': 'failed'}), 401)
	return make_response(jsonify({'task': 'post', 'status': 'failed', 'reason': 'user is banned'}), 403)


@app.route('/users/<int:id_>', methods=['PUT'])
def user_by_id(id_: int):
	"""
	update is_banned (if the user is admin)
	"""
	if request.method == 'PUT':
		get_user_by_id: list[Users] = Users.query.filter_by(id=id_).all()
		if session['is_admin'] is True:
			get_user_by_id[0].is_banned = True
			db.session.commit()
			return make_response(jsonify({'task': 'put', 'status': 'successes'}), 200)
		return make_response(jsonify({'task': 'post', 'status': 'failed', 'reason': 'user is not admin'}), 403)
	return make_response(jsonify({'task': 'put', 'status': 'failed'}), 401)


if __name__ == '__main__':
	app.run(debug=True)
