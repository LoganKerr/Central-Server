from flask import render_template, url_for, flash, redirect, request, jsonify
from central_server import app, db, bcrypt
from central_server.forms import RegistrationForm, LoginForm, UpdateUserForm, AddVotingMachinesForm, RemoveVotingMachineForm, CreateElectionForm, OpenElectionForm, CloseElectionForm, VerifyVoteForm
from central_server.models import User, Voter, Candidate, Election, VotingMachine
from flask_login import login_user, current_user, logout_user, login_required
from datetime import datetime
import requests
import secrets
from collections import defaultdict
from phe import paillier
from Naked.toolshed.shell import execute_js, muterun_js

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
		public_key, private_key = paillier.generate_paillier_keypair()
		election = Election(title=form.title.data, organizer_id=current_user.get_id(), public_key=str(public_key.n), private_key_p=str(private_key.p), private_key_q=str(private_key.q))
		db.session.add(election)
#		user_1 = User.query.filter_by(email=form.candidate_1.data).first()
#		candidate_1 = Candidate(election_id=election.id, user_id=user_1.id, value=-1)
#		db.session.add(candidate_1)
#		user_2 = User.query.filter_by(email=form.candidate_2.data).first()
#		candidate_2 = Candidate(election_id=election.id, user_id=user_2.id, value=1)
#		db.session.add(candidate_2)
		for candidate in form.candidates.data:
			user = User.query.filter_by(email=candidate).first()
			temp = Candidate(election_id=election.id, user_id=user.id)
			db.session.add(temp)
		for voter in form.voters.data:
			user = User.query.filter_by(email=voter).first()
			token = secrets.token_hex(64)
			temp = Voter(election_id=election.id, user_id=user.id, voted=False, authentication_token=token)
			db.session.add(temp)
		db.session.commit()
		flash('Election created', 'success')
		return redirect(url_for('home'))
	return render_template('create_election.html', form=form)

@app.route("/election/", methods=['GET', 'POST'])
@login_required
def election():

	#response = execute_js('central_server/static/js/paillier.js', "test2 512")
	#print(response.stdout)
	#print(jsonify(public_key))
	#print(jsonify(private_key))
	#response = execute_js('central_server/static/js/paillier.js', "test3 128 5 "+str(public_key.n))

	verify_vote_form = None;
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
	else:
		flash("No voting machines online", "danger")
	ciphertexts = defaultdict(lambda: 1)
	nonces = defaultdict(lambda: 1)
	tally = defaultdict(lambda: 1)
	candidate_dict = []
	winners = []
	num_votes = 0
	user_voted = None
	percent_verified = 0
	open_form = OpenElectionForm()
	close_form = CloseElectionForm()
	verified_vote_form = None
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
			data_dict = {'nonce_product': defaultdict(lambda: 1), 'votes': defaultdict(dict)}
			data_dict = get_all_votes(election)
			nonces = defaultdict(lambda: 1)
			ciphertexts = data_dict['votes']
			tally = defaultdict(lambda: 0)
			public_key = paillier.PaillierPublicKey(int(election.public_key))
			private_key = paillier.PaillierPrivateKey(public_key, int(election.private_key_p), int(election.private_key_q))
			for candidate in candidates:
				nonces[candidate.Candidate.id] *= data_dict['nonce_product'][candidate.Candidate.id] 
				for fingerprint in data_dict['votes']:
					ciphertext = int(data_dict['votes'][fingerprint][str(candidate.Candidate.id)])
					tally[candidate.Candidate.id] += paillier.EncryptedNumber(public_key, int(data_dict['votes'][fingerprint][str(candidate.Candidate.id)]), 0)
				candidate.Candidate.votes = private_key.decrypt(tally[candidate.Candidate.id])
				db.session.add(candidate.Candidate)
			election.ended = True
			db.session.add(election)
			db.session.commit()
			flash("Election is now closed", "success")
	if election.ended:
		verify_vote_form = VerifyVoteForm()
		if form_type == "verify" and verify_vote_form.validate_on_submit():
			temp_election_id = int(request.form.get("election"))
			temp_user_id = int(request.form.get("user"))
			temp_voter_id = int(request.form.get("voter"))
			temp_auth_token = request.form.get("authentication_token")
			temp_voter = Voter.query.filter_by(id=temp_voter_id).filter_by(election_id=temp_election_id).filter_by(user_id=temp_user_id).filter_by(authentication_token=temp_auth_token).filter_by(voted=True).filter_by(verified=False).first()
			if (temp_voter != None):
				temp_voter.verified=True
				if request.form.get("vote_exists"):
					temp_voter.vote_exists=True
				db.session.add(temp_voter)
				db.session.commit()
		user_voted = Voter.query.filter_by(election_id=election.id).filter_by(voted=True).filter_by(user_id=current_user.id).first()
		if (user_voted != None and user_voted.verified == False):
			flash("Please verify if you see your vote", "info")
		num_votes = 0
		max_votes = 0
		for candidate in candidates:
			num_votes += candidate.Candidate.votes
			if candidate.Candidate.votes > max_votes:
				max_votes = candidate.Candidate.votes
		for candidate in candidates:
			if candidate.Candidate.votes == max_votes:
				winners.append(candidates)
		data_dict = {'nonce_product': defaultdict(lambda: 1), 'votes': defaultdict(dict)}
		data_dict = get_all_votes(election)
		nonces = defaultdict(lambda: 1)
		ciphertexts = data_dict['votes']
		tally = defaultdict(lambda: 0)
		public_key = paillier.PaillierPublicKey(int(election.public_key))
		private_key = paillier.PaillierPrivateKey(public_key, int(election.private_key_p), int(election.private_key_q))
		for candidate in candidates:
			nonces[candidate.Candidate.id] *= data_dict['nonce_product'][candidate.Candidate.id] 
			for fingerprint in data_dict['votes']:
				#print ("VOTE: ", data_dict['votes'][fingerprint])
				tally[candidate.Candidate.id] += paillier.EncryptedNumber(public_key, int(data_dict['votes'][fingerprint][str(candidate.Candidate.id)]))		

		voted_voters = Voter.query.filter_by(election_id=election.id).filter_by(voted=True).all()
		ax = 0
		max = num_votes
		for voter in voted_voters:
			if voter.verified==True and voter.vote_exists==True:
				ax+=1
		percent_verified = ax * 100 / max
		if (num_votes != len(voted_voters)):
			flash("Warning: Number of votes cast does not match number of voters who voted", "danger")

		nonces=nonces_to_dict(nonces)
		tally=encrypted_numbers_to_dict(tally)
		candidate_dict=candidates_to_dict(candidates)
	return render_template('election.html', election=election, organizer=organizer, candidates=candidates, voters=voters, open_form=open_form, close_form=close_form, voting_link=voting_link, votes=ciphertexts, nonces=nonces, tally=tally, candidate_dict=candidate_dict, winners=winners, num_votes=num_votes, user_voted=user_voted, percent_verified=percent_verified, verify_vote_form=verify_vote_form)

def get_all_votes(election):
	data_dict = {'nonce_product': defaultdict(lambda: 1), 'votes': defaultdict(dict)}
	mach_data_dict = {}
	voting_machines = VotingMachine.query.all()
	for machine in voting_machines:
		mach_data_dict = get_votes_from(machine.port, election.id)
		for candidate in mach_data_dict['nonce_product']:
			data_dict['nonce_product'][int(candidate)] *= mach_data_dict['nonce_product'][candidate]
		for fingerprint in mach_data_dict['votes']:
			data_dict['votes'][fingerprint] = mach_data_dict['votes'][fingerprint]
	return data_dict

def get_votes_from(port, election_id):
	votes = {}
	try:
		response = requests.get("http://localhost:"+str(port)+"/get_votes/?election_id="+str(election_id))
		print(response)
		votes = response.json()
	except requests.exceptions.RequestException as e:
		print(e)
	return votes

def encrypted_numbers_to_dict(enc_numbers):
	res_dict = {}
	for candidate_id in enc_numbers:
		res_dict[candidate_id] = str(enc_numbers[candidate_id].ciphertext(False))
	return res_dict

def candidates_to_dict(candidates):
	res_dict = {}
	for candidate in candidates:
		res_dict[candidate.Candidate.id] = candidate.Candidate.votes;
	return res_dict

def nonces_to_dict(nonces):
	res_dict = {}
	for nonce in nonces:
		res_dict[nonce] = str(nonces[nonce])
	return res_dict

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

@app.route("/voter_voted/", methods=['GET', 'POST'])
def voter_voted():
	status = False
	if request.remote_addr != "127.0.0.1":
		return jsonify({})
	voter_id = int(request.args.get("voter_id"))
	authentication_token = request.args.get("authentication_token")
	voter = Voter.query.filter_by(id=voter_id, authentication_token=authentication_token, voted=False).first()
	if voter != None:
		voter.voted = True
		db.session.add(voter)
		db.session.commit()
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