from flask import Flask, render_template, request, redirect, session
import jinja2
from pymongo import *
import os
from secret import *

app = Flask(__name__)

app.secret_key = APP_SECRET
client = MongoClient(MONGO_CRED)
db = client.get_default_database()
users = db.users

def session_logout():
	session.pop('username', None)
	session.pop('name', None)

def logged_in():
	if session.get('username') is None:
		session_logout()
		return False
	return True

@app.route('/')
def hello():
	return render_template("index.html",signed_in=logged_in())

if __name__ == '__main__':
	port = int(os.environ.get('PORT', 8000))
	app.run(host='0.0.0.0', port=port,debug=True)