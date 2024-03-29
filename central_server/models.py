from datetime import datetime
from central_server import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(user_id)

class VotingMachine(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(60), nullable=False)
	port = db.Column(db.Integer, nullable=False)
	status = db.Column(db.Boolean, nullable=False)
	last_checked = db.Column(db.DateTime, nullable=False)

class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	email = db.Column(db.String(120), nullable=False, unique=True)
	password = db.Column(db.String(60), nullable=False)
	voters = db.relationship('Voter', backref='user', lazy=True)
	organizers = db.relationship('Election', backref='organizer', lazy=True)
	candidates = db.relationship('Candidate', backref='candidate', lazy=True)

	def __repr__(self):
		return f"User:('{self.email}')"

class Voter(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	voted = db.Column(db.Boolean, nullable=False)
	authentication_token = db.Column(db.String(128), nullable=False)
	verified = db.Column(db.Integer, nullable=False, default=False)
	vote_exists = db.Column(db.Integer, nullable=False, default=False)

	def __repr__(self):
		return f"Voter:('{self.election_id}', '{self.user_id}', '{self.voted}', '{self.authentication_token}')"

class Candidate(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	election_id = db.Column(db.Integer, db.ForeignKey('election.id'), nullable=False)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	votes = db.Column(db.Integer, nullable=False, default=0)

	def __repr__(self):
		return f"Candidate:('{self.election_id}', '{self.user_id}','{self.votes}')"

class Election(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(120), nullable=False)
	organizer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
	started = db.Column(db.Boolean, nullable=False, default=False)
	ended = db.Column(db.Boolean, nullable=False, default=False)
	public_key = db.Column(db.String(1024), nullable=False)
	private_key_p = db.Column(db.String(1024), nullable=False)
	private_key_q = db.Column(db.String(1024), nullable=False)
	voters = db.relationship('Voter', backref='election', lazy=True)
	candidates = db.relationship('Candidate', backref='election', lazy=True)

	def __repr__(self):
		return f"Election:('{self.title}', '{self.organizer_id}', '{self.started}', '{self.ended}' '{self.public_key}')"