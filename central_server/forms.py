from flask_wtf import FlaskForm
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, FieldList
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from central_server.models import User, VotingMachine

class RegistrationForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired()])
	password_confirmation = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Register')

	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user:
			raise ValidationError('Email address is taken')

class LoginForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Password', validators=[DataRequired()])
	remember = BooleanField('Remember Me')
	submit = SubmitField('Login')

class UpdateUserForm(FlaskForm):
	email = StringField('Email', validators=[])
	password = PasswordField('Password', validators=[Optional()])
	password_confirmation = PasswordField('Confirm Password', validators=[Optional(), EqualTo('password')])
	submit = SubmitField('Update')

	def validate_email(self, email):
		if email != current_user.email:
			user = User.query.filter_by(email=email.data).first()
			if user:
				raise ValidationError('Email address is taken')

class AddVotingMachinesForm(FlaskForm):
	name = StringField('Name', validators=[DataRequired()])
	port = IntegerField('Port', validators=[DataRequired()])
	submit = SubmitField('Submit')

	def validate_port(self, port):
		machine = VotingMachine.query.filter_by(port=port.data).first()
		if machine:
			raise ValidationError('Voting Machine with port already exists')

class RemoveVotingMachineForm(FlaskForm):
	submit = SubmitField('Remove')

class CreateElectionForm(FlaskForm):
	title = StringField('Title', validators=([DataRequired()]))
	candidates = FieldList(StringField())
	voters = FieldList(StringField())
	submit = SubmitField('Create Election')

	def validate_candidates(self, candidates):
		if len(candidates) < 2:
			raise ValidationError('Add at least one candidate')
		for candidate in candidates.data:
			user = User.query.filter_by(email=candidate).first()
			if user == None:
				raise ValidationError('Candidate not found with email: '+candidate)

	def validate_voters(self, voters):
		if len(voters) < 1:
			raise ValidationError('Add at least one voter')
		for voter in voters.data:
			user = User.query.filter_by(email=voter).first()
			if user == None:
				raise ValidationError('Voter not found with email: '+voter)

class OpenElectionForm(FlaskForm):
	submit = SubmitField('Open Election')

class CloseElectionForm(FlaskForm):
	submit = SubmitField('Close Election')