
from flask import Flask, render_template, request, redirect, session
import jinja2
from pymongo import *
import os
from utils import *
import ast

app = Flask(__name__)

app.secret_key = os.environ["APP_SECRET"]
client = MongoClient(os.environ["MONGO_CRED"])
db = client.get_default_database()
users = db.users
tutor_sessions = db.tutor_sessions

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

@app.route('/add', methods=['GET', 'POST'])
def add():
	if request.method == 'POST':
		sessions = {}
		for field in request.form:
			value = request.form.get(field).strip()
			if value != '' and MODS_NAME_RE.match(field):
				if not(MODS_RE.match(value)):
					return render_template('add.html',error='Please enter mods correctly')
			if SUBJECT_RE.match(field) and value == None:
				return render_template('add.html',error='Cannot leave any field blank')
			if SUBJECT_RE.match(field) and value not in sessions:
				number = field.replace('subject','')
				sessions[value] = {'monday':request.form.get('mods_monday_'+number),'tuesday':request.form.get('mods_tuesday_'+number),
								'wednesday':request.form.get('mods_wednesday_'+number), 'thursday':request.form.get('mods_thursday_'+number),
								'friday':request.form.get('mods_friday_'+number)}
		for course in sessions:
			tutor_sessions.insert({'session':course,'monday':sessions[course]['monday'],'tuesday':sessions[course]['tuesday'],
					'wednesday':sessions[course]['wednesday'],'thursday':sessions[course]['thursday'],'friday':sessions[course]['friday'],
					'tutor':session.get('name'),'tutor_username':session.get('username')})
		return redirect('/')
	if not logged_in():
		return redirect('/signin')
	return render_template('add.html',signed_in=logged_in())

@app.route('/view', methods=['GET', 'POST'])
def view():
	if request.method == 'POST':
		subject = request.form.get('subject')
		return redirect('/view/'+subject)
	return render_template('view.html',signed_in=logged_in())

@app.route('/view/<subject>/')
def view_subject(subject):
	if subject == None:
		return redirect('/')
	subject_data = tutor_sessions.find({'session':subject})
	monday = {'1-3':[],'4-6':[],'7-9':[],'10-12':[],'13-15':[],'16-18':[],'19-21':[],'22-24':[],'25-27':[]}
	tuesday = {'1-3':[],'4-6':[],'7-9':[],'10-12':[],'13-15':[],'16-18':[],'19-21':[],'22-24':[],'25-27':[]}
	wednesday = {'1-3':[],'4-6':[],'7-9':[],'10-12':[],'13-15':[],'16-18':[],'19-21':[],'22-24':[],'25-27':[]}
	thursday = {'1-3':[],'4-6':[],'7-9':[],'10-12':[],'13-15':[],'16-18':[],'19-21':[],'22-24':[],'25-27':[]}
	friday = {'1-3':[],'4-6':[],'7-9':[],'10-12':[],'13-15':[],'16-18':[],'19-21':[],'22-24':[],'25-27':[]}
	if subject_data == None:
		return render_template('view_subject.html',signed_in=logged_in(),subject=subject, monday=monday,tuesday=tuesday,
			wednesday=wednesday,thursday=thursday,friday=friday)
	for ses in subject_data:
		if str(ses['monday']) != '':
			ses['monday'] = str(ses['monday']).split(',')
			for s in ses['monday']: 
				s = s.strip()
				try:
					monday[str(s)].append(str(ses['tutor'])+'-'+str(ses['tutor_username'])+'@bergen.org')
				except KeyError:
					pass
		if str(ses['tuesday']) != '':
			ses['tuesday'] = str(ses['tuesday']).split(', ')
			for s in ses['tuesday']:
				s = s.strip()
				try:
					tuesday[str(s)].append(str(ses['tutor'])+'-'+str(ses['tutor_username'])+'@bergen.org')
				except KeyError:
					pass
		if str(ses['wednesday']) != '':
			ses['wednesday'] = str(ses['wednesday']).split(', ')
			for s in ses['wednesday']:
				s = s.strip()
				try:
					wednesday[str(s)].append(str(ses['tutor'])+'-'+str(ses['tutor_username'])+'@bergen.org')
				except KeyError:
					pass
		if str(ses['thursday']) != '':
			ses['thursday'] = str(ses['thursday']).split(', ')
			for s in ses['thursday']:
				s = s.strip()
				try:
					thursday[str(s)].append(str(ses['tutor'])+'-'+str(ses['tutor_username'])+'@bergen.org')
				except KeyError:
					pass
		if str(ses['friday']) != '':
			ses['friday'] = str(ses['friday']).split(', ')
			for s in ses['friday']:
				s = s.strip()
				try:
					friday[str(s)].append(str(ses['tutor'])+'-'+str(ses['tutor_username'])+'@bergen.org')
				except KeyError:
					pass
	return render_template('view_subject.html',signed_in=logged_in(),subject=subject, monday=monday,tuesday=tuesday,
			wednesday=wednesday,thursday=thursday,friday=friday)

@app.route('/my-sessions', methods=['GET', 'POST'])
def my_ses():
	if not(logged_in()):
		return redirect('/')
	query = tutor_sessions.find({'tutor':session.get('name'),'tutor_username':session.get('username')})
	data = []
	for ses in query:
		del ses['_id']
		data.append(ses)
	return render_template('my_sessions.html',data=data,signed_in=logged_in())

@app.route('/delete', methods=['GET', 'POST'])
def delete_ses():
	if request.method == 'POST':
		try:
			data = ast.literal_eval(request.form.get('data'))
		except Exception, e:
			return redirect('/')
		if not(data['tutor_username'] == session.get('username')) and not(session.get('admin')):
			return redirect('/')
		tutor_sessions.remove(data)
		if session.get('admin'):
			return redirect('/admin')
		return redirect('/my-sessions')
	return redirect('/my-sessions')

@app.route('/signup/tutor', methods=['GET', 'POST'])
def tutor():
	if request.method == 'POST':
		full_name = request.form.get('full_name')
		username = request.form.get('username').lower()
		if '@bergen.org' in username:
			username = username.split("@bergen.org")[0]
		password = request.form.get('password')
		password_confirm = request.form.get('password_confirm')
		key = request.form.get('key')
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
		if key != 'NHStutor':
			return render_template('signup_tutor.html', variables=variables, key_error="Enter the correct key")
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
	return render_template('signup_tutor.html',signed_in=logged_in())

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
		return redirect('/add')
	if logged_in():
		return redirect('/')
	return render_template('signin.html',signed_in=logged_in())

@app.route('/logout')
def sign_out():
	session_logout()
	return redirect('/')

@app.errorhandler(404)
def missing(error):
	return render_template('404.html', signed_in=logged_in()), 404

@app.route('/404')
def fourofour():
	return render_template('404.html', signed_in=logged_in()), 404

@app.errorhandler(500)
def broken(error):
	return render_template('500.html'), 500

@app.route('/500')
def fivehundred():
	return render_template('500.html'), 500

@app.route('/admin',methods=['GET', 'POST'])
def admin():
	if request.method == 'POST':
		password = request.form.get('password')
		if password == 'bcanhs12':
			session['admin'] = True
			query = tutor_sessions.find({})
			data = []
			for ses in query:
				del ses['_id']
				data.append(ses)
			return render_template('all_sessions.html',signed_in=logged_in(),data=data)
		return redirect('/admin')
	if session.get('admin'):
		query = tutor_sessions.find({})
		data = []
		for ses in query:
			del ses['_id']
			data.append(ses)
		return render_template('all_sessions.html',signed_in=logged_in(),data=data)
	return render_template('admin_pass.html',signed_in=logged_in())

@app.route('/points')
def points():
	return render_template('points.html')

@app.route('/officers')
def officers():
	return render_template('officers.html')

# @app.route('/meeting-minutes')
# def minutes():
# 	return render_template('minutes.html')

@app.route('/officer-videos')
def officerVideos():
	return render_template('officer-videos.html')

@app.route('/requirements')
def requirements():
	return render_template('requirements.html')

@app.route('/bylaws')
def bylaws():
	return render_template('bylaws.html')

@app.route('/signoff-sheet')
def sheet():
	return redirect('https://drive.google.com/file/d/0B-b_N1cpnpZ7WHAwcy1zd3ZaUmc/view?usp=sharing')

if __name__ == '__main__':
	port = int(os.environ.get('PORT', 8000))
	debug = True
	if 'DYNO' in os.environ:
	    debug = False
	app.run(host='0.0.0.0', port=port, debug=debug)