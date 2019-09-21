from flask import render_template, url_for, flash, redirect, request
from central_server import app, db, bcrypt
from central_server.forms import RegistrationForm, LoginForm, UpdateUserForm, AddVotingMachinesForm, RemoveVotingMachineForm
from central_server.models import User, Voter, Candidate, Election, VotingMachine
from flask_login import login_user, current_user, logout_user, login_required
from datetime import datetime
import requests

@app.route("/")
def home():
    return render_template('home.html')

@app.route("/register/", methods=['GET', 'POST'])
def register():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = RegistrationForm()
	if form.validate_on_submit():
		hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		user = User(email=form.email.data, password=hash)
		db.session.add(user)
		db.session.commit()
		flash("Account created", "success")
		return redirect(url_for('login'))
	return render_template('register.html', form=form)

@app.route("/login/", methods=['GET', 'POST'])
def login():
	if current_user.is_authenticated:
		return redirect(url_for('home'))
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(email=form.email.data).first()
		if user and bcrypt.check_password_hash(user.password, form.password.data):
			login_user(user, remember=form.remember.data)
			next_page = request.args.get('next')
			flash("Logged in", "success")
			if (next_page):
				return redirect(next_page)
			else:
				return redirect(url_for('home'))
		else:
			flash("Username or password is incorrect", "danger")
	return render_template('login.html', form=form)

@app.route("/profile/", methods=['GET', 'POST'])
@login_required
def profile():
	form = UpdateUserForm()
	if form.validate_on_submit():
		changed = False
		if form.email.data:
			current_user.email = form.email.data
			changed = True
		if form.password.data and form.password.data == form.password_confirmation.data:
			current_user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
			changed = True
		if changed:
			db.session.commit()
			flash("Profile updated", "success")
	return render_template('profile.html', form=form)

@app.route("/logout/")
def logout():
	logout_user()
	return redirect(url_for('home'))

@app.route("/voting_machines/", methods=['GET', 'POST'])
def voting_machines():
	form2 = RemoveVotingMachineForm()
	form = AddVotingMachinesForm()
	form_type = request.form.get('type')
	print(form_type)
	if form_type == "remove" and form2.validate_on_submit():
		port = request.form.get('rport')
		print(port)
		voting_machine = VotingMachine.query.filter_by(port=int(port)).first()
		print(voting_machine)
		if voting_machine:
			db.session.delete(voting_machine)
			db.session.commit()
			flash("Voting Machine Removed")
		else:
			flash("Voting Machine not found")
	if form_type == "add" and form.validate_on_submit():
		status = getStatusOfVM(int(form.port.data))
		voting_machine = VotingMachine(name=form.name.data, port=int(form.port.data), last_checked=datetime.utcnow(), status=status)
		db.session.add(voting_machine)
		db.session.commit()
		flash("Voting Machine Added")
	voting_machines = VotingMachine.query.all()
	for machine in voting_machines:
		status = getStatusOfVM(machine.port)
		machine.status = status
		machine.last_checked = datetime.utcnow()
	db.session.commit()
	return render_template('voting_machines.html', voting_machines=voting_machines, form=form, form2=form2)

def getStatusOfVM(port):
	response = 0
	try:
		response = requests.get('http://localhost:'+str(port))
	except requests.exceptions.RequestException as e:  # This is the correct syntax
		print(e)
	return response and response.ok