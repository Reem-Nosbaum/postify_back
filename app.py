from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

CORS(app)


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
