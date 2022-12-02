from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import datetime

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///postify.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
CORS(app)


class Users(db.Model):
	id = db.Column(db.BigInteger, primary_key=True)
	username = db.Column(db.Text, unique=True, nullable=False)
	password = db.Column(db.Text, nullable=False)
	is_admin = db.Column(db.Boolean, nullable=False)
	is_banned = db.Column(db.Boolean, nullable=False)

class Subjects(db.Model):
	id = db.Column(db.BigInteger, primary_key=True)
	subject = db.Column(db.Text, unique=True, nullable=False)

class Groups(db.Model):
	id = db.Column(db.BigInteger, primary_key=True)
	groups = db.Column(db.Text, unique=True, nullable=False)

class Posts(db.Model):
	id = db.Column(db.BigInteger, primary_key=True)
	user = db.Column(db.BigInteger, db.ForeignKey('users.id'),nullable=False)
	subject = db.Column(db.BigInteger, db.ForeignKey('subjects.id'),nullable=False)
	body = db.Column(db.Text, nullable=False)
	group = db.Column(db.BigInteger, db.ForeignKey('groups.id'))
	time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)


@app.route('/signup', methods=['POST'])
def signup():
	...


@app.route('/login', methods=['POST'])
def login():
	...


@app.route('/logout', methods=['POST'])
def logout():
	...


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
