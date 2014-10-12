from flask import Flask, render_template, request, redirect, session
import jinja2
from pymongo import *
import os
from secret import *
from utils import *

app = Flask(__name__)

app.secret_key = APP_SECRET
client = MongoClient(MONGO_CRED)
db = client.get_default_database()
users = db.users

def session_login(username, first_name):
	session['username'] = username
	session['name'] = first_name
	session.permanent = True

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

@app.route('/signup/tutor', methods=['GET', 'POST'])
def tutor():
	if request.method == 'POST':
		full_name = request.form.get('full_name')
		username = request.form.get('username').lower()
		if '@bergen.org' in username:
			username = username.split("@bergen.org")[0]
		password = request.form.get('password')
		password_confirm = request.form.get('password_confirm')
		variables = {"full_name" : full_name, "username" : username}
		if not full_name:
			return render_template('signup_tutor.html', variables=variables, full_name_error="Please enter a name.")
		if not username:
			return render_template('signup_tutor.html', variables=variables, username_error="Please enter a username.")
		if not password:
			return render_template('signup_tutor.html', variables=variables, password_error="Please enter a password.")
		if not password_confirm:
			return render_template('signup_tutor.html', variables=variables, password_confirm_error="Please re-type your password.")
		if not valid_username(username):
			return render_template('signup_tutor.html', variables=variables, username_error="Enter a valid username.")
		if not valid_password(password):
			return render_template('signup_tutor.html', variables=variables, password_error="Enter a valid password.")
		if password != password_confirm:
			return render_template('signup_tutor.html', variables=variables, password_confirm_error="Passwords must match")
		result = users.find_one({"username":username})
		if not result is None:
			if valid_pw(username, password, result.get('password')):
				session['username'] = username
				session['name'] = result.get('name')
				return redirect('/')
			else:
				return render_template('signup_tutor.html', variables=variables, username_error="Username taken.")
		password = make_pw_hash(username,password)
		user_id = users.insert({"username": username,"password": password,"name":full_name})
		session_login(username, full_name)
		return redirect('/')
	if logged_in():
		return redirect('/')
	return render_template('signup_tutor.html')
@app.route('/signup/student', methods=['GET', 'POST'])
def student():
	return render_template('signup_student.html')
@app.route('/signin', methods=['GET', 'POST'])
def sign_in():
	if request.method == 'POST':
		username = request.form.get('username').lower()
		if '@bergen.org' in username:
			username = username.split("@bergen.org")[0]
		password = request.form.get('password')
		if not(username):
			return render_template('signin.html', username_error="No username found.")
		if not(password):
			return render_template('signin.html', password_error="No password found.", username=username)
		user = users.find_one({'username':username})
		if user is None:
			return render_template('signin.html', username_error="No account found!", username=username)
		if not(valid_pw(username,password,user.get('password'))):
			return render_template('signin.html', error="Invalid username and password.", username=username)
		session_login(username, user.get('name'))
		return redirect('/')
	if logged_in():
		return redirect('/')
	return render_template('sign_in.html')
@app.route('/logout')
def sign_out():
	session_logout()
	return redirect('/')
if __name__ == '__main__':
	port = int(os.environ.get('PORT', 8000))
	app.run(host='0.0.0.0', port=port,debug=True)