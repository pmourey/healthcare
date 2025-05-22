from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional, Match

from dateutil.relativedelta import relativedelta
from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy.model import Model
from sqlalchemy import DateTime, ForeignKey, Column, Float, Integer, String, Boolean, Text
from sqlalchemy.orm import relationship, validates
from werkzeug.security import generate_password_hash

db = SQLAlchemy()


class Role(Enum):
	ADMIN = 0
	EDITOR = 1
	READER = 2


class HealthData(db.Model):
	__tablename__ = 'health_data'
	id = Column(Integer, primary_key=True)
	weight = Column(Float, nullable=False)
	height = Column(Float, nullable=False)
	heart_rate = Column(Integer, nullable=False)
	# blood_pressure = Column(String(10), nullable=False)
	blood_pressure_sys = Column(Integer, nullable=False)
	blood_pressure_dia = Column(Integer, nullable=False)
	temperature = Column(Float, nullable=False)
	notes = Column(Text, nullable=True)
	creation_date = Column(DateTime, nullable=False)
	# Define a foreign key column referencing the 'patient' table
	patient_id = Column(Integer, ForeignKey('patients.id'), nullable=False)

	@property
	def imc(self) -> float:
		return round(self.weight / ((self.height / 100) ** 2), 1)


class Patient(db.Model):
	__tablename__ = 'patients'
	id = Column(Integer, primary_key=True)
	first_name = Column(String(20), nullable=False)
	last_name = Column(String(20), nullable=False)
	# email = Column(String(120), unique=True, nullable=False)
	email = Column(String(120), nullable=False)
	phone = Column(String(20), nullable=False)
	creation_date = Column(DateTime, nullable=False)
	user_id = Column(Integer, ForeignKey('user.id'), nullable=False)

	health_data = relationship('HealthData', backref='patient', cascade='all, delete-orphan')
	blood_data = relationship('AnalyseSanguine', backref='patient', cascade='all, delete-orphan')


class AnalyseSanguine(db.Model):
	__tablename__ = 'analyses'
	id = Column(Integer, primary_key=True)
	patient_id = Column(Integer, ForeignKey('patients.id'))
	# date_analyse = Column(DateTime, default=datetime.now)
	date_analyse = Column(DateTime, nullable=False)

	# Marqueurs biologiques
	hemoglobine = Column(Float)  # g/dL
	hematocrite = Column(Float)  # %
	globules_blancs = Column(Integer)  # /mm3
	globules_rouges = Column(Integer)  # /mm3
	plaquettes = Column(Integer)  # /mm3
	creatinine = Column(Float)  # mg/L
	uree = Column(Integer)  # mg/L
	glycemie = Column(Float)  # g/L
	cholesterol_total = Column(Float)  # g/L
	hdl = Column(Float)  # g/L
	ldl = Column(Float)  # g/L
	triglycerides = Column(Float)  # g/L
	tsh = Column(Float)  # mUI/L
	psa = Column(Float)  # ng/mL
	alt = Column(Integer)  # UI/L
	ast = Column(Integer)  # UI/L
	fer = Column(Float)  # µg/dL
	vitamine_d = Column(Integer)  # ng/mL


class User(db.Model):
	__tablename__ = 'user'
	id = Column(Integer, primary_key=True)
	username = Column(String(20), unique=True, nullable=False)
	password = Column(String(60), nullable=False)
	role = Column(Integer)
	creationDate = Column(DateTime, nullable=False)
	email = Column(String(120), unique=True, nullable=False)
	recovery_token = Column(String(128))
	token_expiration = Column(DateTime)
	validated = Column(Boolean, default=False)

	patients = relationship('Patient', backref='user', lazy='dynamic', cascade='all, delete-orphan')
	sessions = relationship('Session', backref='user', lazy='dynamic')

	def __repr__(self):
		return f'{self.username}:{self.password} ({Role(self.role)})'

	def __init__(self, username: str, password: str, creation_date: DateTime, email: str):
		self.username = username
		# self.password = generate_password_hash(password, method='pbkdf2:sha256')
		self.password = generate_password_hash(password)
		self.creationDate = creation_date
		self.email = email
		self.role = Role.READER.value

	# @validates('email')
	# def validate_email(self, email):
	#     return email.lower() if email else None

	@validates('email')
	def validates(self, key, email):
		if email is None:
			return None

		# Remove leading/trailing whitespace
		email = email.strip()

		# Email pattern regex
		pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

		if not re.match(pattern, email):
			raise ValueError('Invalid email format')

		return email.lower()

	@property
	def is_admin(self):
		return Role(self.role) == Role.ADMIN

	@property
	def is_editor(self):
		return Role(self.role) == Role.EDITOR

	@property
	def is_reader(self):
		return Role(self.role) == Role.READER

	@property
	def status(self) -> str:
		# Get the latest session for this user
		latest_session = Session.query.filter(Session.login_id == self.id).order_by(Session.start.desc()).first()

		if not latest_session:
			return "Never connected"

		if latest_session.end is None:
			# Active session - show how long they've been connected
			delta = relativedelta(datetime.now(), latest_session.start)

			if delta.days > 0:
				return f'Connected for {delta.days} days'
			elif delta.hours > 0:
				return f'Connected for {delta.hours} hours'
			elif delta.minutes > 0:
				return f'Connected for {delta.minutes} minutes'
			else:
				return f'Connected for {delta.seconds} seconds'
		else:
			# Ended session - show how long ago they disconnected
			delta = relativedelta(datetime.now(), latest_session.end)

			if delta.days > 0:
				return f'Last seen {delta.days} days ago'
			elif delta.hours > 0:
				return f'Last seen {delta.hours} hours ago'
			elif delta.minutes > 0:
				return f'Last seen {delta.minutes} minutes ago'
			else:
				return f'Last seen {delta.seconds} seconds ago'


@dataclass
class BrowserInfo:
	family: str
	version: str


class Session(db.Model):
	__tablename__ = 'sessions'
	id = Column(Integer, primary_key=True, autoincrement=True)
	start = Column(DateTime, nullable=False)
	end = Column(DateTime, nullable=True)
	client_ip = Column(String(15), nullable=False)
	browser_family = Column(String(20), nullable=False)
	browser_version = Column(String(10), nullable=False)
	login_id = Column(Integer, ForeignKey('user.id'), nullable=False)

	def __init__(self, login_id: int, start: DateTime, client_ip: str, browser_family: str, browser_version: str):
		self.login_id = login_id
		self.start = start
		self.end = None
		self.client_ip = client_ip
		self.browser_family = browser_family
		self.browser_version = browser_version

	def __repr__(self):
		user: User = User.query.get(self.login_id)
		if not self.end:
			return f'{user.username} connecté depuis: {self.start}'
		else:
			return f'{user.username} déconnecté à: {self.end}'

	@property
	def username(self) -> str:
		return User.query.get(self.login_id).username

	@property
	def is_valid(self) -> bool:
		# Query to find the latest active session with the same characteristics
		latest_session = Session.query.filter(Session.client_ip == self.client_ip,
											  Session.browser_family == self.browser_family,
											  Session.browser_version == self.browser_version,
											  Session.login_id == self.login_id,
											  Session.end.is_(None)  # Check for active sessions only
											  ).order_by(Session.start.desc()).first()

		# Check if this session is the latest active one
		return latest_session and latest_session.id == self.id

