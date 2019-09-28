from flask import render_template, url_for, flash, redirect, request, jsonify
from central_server import app, db, bcrypt
from central_server.forms import RegistrationForm, LoginForm, UpdateUserForm, AddVotingMachinesForm, RemoveVotingMachineForm, CreateElectionForm, OpenElectionForm, CloseElectionForm
from central_server.models import User, Voter, Candidate, Election, VotingMachine
from flask_login import login_user, current_user, logout_user, login_required
from datetime import datetime
import requests
import secrets

@app.route("/")
@login_required
def home():
	elections = {}
	organizer_elections = Election.query.filter_by(organizer_id=current_user.id).all()
	candidate_elections = db.session.query(Election).join(Candidate).join(User).filter_by(id=current_user.get_id()).all()
	voter_elections = db.session.query(Election).join(Voter).join(User).filter_by(id=current_user.get_id()).all()
	elections["organizer"] = organizer_elections
	elections["candidate"] = candidate_elections
	elections["voter"] = voter_elections
	return render_template('home.html', elections=elections)

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
@login_required
def voting_machines():
	form2 = RemoveVotingMachineForm()
	form = AddVotingMachinesForm()
	form_type = request.form.get('type')
	if form_type == "remove" and form2.validate_on_submit():
		port = request.form.get('rport')
		voting_machine = VotingMachine.query.filter_by(port=int(port)).first()
		if voting_machine:
			db.session.delete(voting_machine)
			db.session.commit()
			flash("Voting Machine Removed", "success")
		else:
			flash("Voting Machine not found", "danger")
	if form_type == "add" and form.validate_on_submit():
		status = getStatusOfVM(int(form.port.data))
		voting_machine = VotingMachine(name=form.name.data, port=int(form.port.data), last_checked=datetime.utcnow(), status=status)
		db.session.add(voting_machine)
		db.session.commit()
		flash("Voting Machine Added", "success")
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
	except requests.exceptions.RequestException as e:
		print(e)
	return response and response.ok

@app.route("/create_election/", methods=['GET', 'POST'])
@login_required
def create_election():
	form = CreateElectionForm()
	if form.validate_on_submit():
		election = Election(title=form.title.data, organizer_id=current_user.get_id(), public_key="", private_key="")
		db.session.add(election)
		for candidate in form.candidates.data:
			user = User.query.filter_by(email=candidate).first()
			temp = Candidate(election_id=election.id, user_id=user.id)
			db.session.add(temp)
		for voter in form.voters.data:
			user = User.query.filter_by(email=voter).first()
			token = secrets.token_hex(128)
			temp = Voter(election_id=election.id, user_id=user.id, voted=False, authentication_token=token)
			db.session.add(temp)
		db.session.commit()
		flash('Election created', 'success')
		return redirect(url_for('home'))
	return render_template('create_election.html', form=form)

@app.route("/election/", methods=['GET', 'POST'])
@login_required
def election():
	id = request.args.get("id")
	election = Election.query.filter_by(id=id).first()
	if election == None:
		flash('Election not found', "danger")
		return redirect(url_for('home'))
	organizer = User.query.filter_by(id=election.organizer_id).first()
	candidates = db.session.query(Candidate, User).filter_by(election_id=election.id).join(User, User.id == Candidate.user_id).all()
	voters = db.session.query(Voter, User).filter_by(election_id=election.id).join(User, User.id == Voter.user_id).all()
	vm = VotingMachine.query.filter_by(status=True).first()
	voting_link = "#"
	if vm != None:
		voting_link = "http://localhost:"+str(vm.port)+"/vote/"
	open_form = OpenElectionForm()
	close_form = CloseElectionForm()
	form_type = request.form.get('type')
	if form_type == "open" and open_form.validate_on_submit():
		election = Election.query.filter_by(id=election.id).filter_by(organizer_id=current_user.get_id()).filter_by(started=False).filter_by(ended=False).first()
		if election != None:
			election.started = True
			db.session.add(election)
			db.session.commit()
			flash("Election is now open", "success")
	if form_type == "close" and close_form.validate_on_submit():
		election = Election.query.filter_by(id=election.id).filter_by(organizer_id=current_user.get_id()).first()
		if election != None:
			flash("Election is now closed", "success")
			election.started = True
			election.ended = True
			db.session.add(election)
			db.session.commit()
	return render_template('election.html', election=election, organizer=organizer, candidates=candidates, voters=voters, open_form=open_form, close_form=close_form, voting_link=voting_link)

@app.route("/vm_check/", methods=['GET', 'POST'])
def vm_check():
	if request.remote_addr != "127.0.0.1":
		return jsonify({})
	status = False
	election_id = int(request.args.get("election"))
	voter_id = int(request.args.get("voter"))
	authentication_token = request.args.get("authentication_token")
	election = Election.query.filter_by(id=election_id).first()
	if election != None and (election.started and not election.ended):
		voter = Voter.query.filter_by(id=voter_id).filter_by(election_id=election_id).filter_by(authentication_token=authentication_token).filter_by(voted=False).first()
		if voter != None:
			status = True
	data = {'status': status}
	return jsonify(data)

@app.route("/get_election/", methods=['GET', 'POST'])
def get_election():
	if request.remote_addr != "127.0.0.1":
		return jsonify({})
	election_id = int(request.args.get("election"))
	election = Election.query.filter_by(id=election_id).first()
	candidates = db.session.query(Candidate, User).filter_by(election_id=election_id).join(User, User.id == Candidate.user_id).all()
	candidates_list = []
	for candidate in candidates:
		candidates_list.append({'id' : candidate.Candidate.id, 'email' : candidate.User.email})
	data = {'election' : {'id': election.id, 'title' : election.title, 'pub_key': election.public_key}, 'candidates' : candidates_list }
	return jsonify(data)