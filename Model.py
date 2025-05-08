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
from sqlalchemy import DateTime, ForeignKey
from sqlalchemy.orm import relationship, validates
from werkzeug.security import generate_password_hash

db = SQLAlchemy()


class Role(Enum):
	ADMIN = 0
	EDITOR = 1
	READER = 2

class HealthData(db.Model):
	__tablename__ = 'health_data'
	id = db.Column(db.Integer, primary_key=True)
	weight = db.Column(db.Float, nullable=False)
	height = db.Column(db.Float, nullable=False)
	heart_rate = db.Column(db.Integer, nullable=False)
	blood_pressure = db.Column(db.String(10), nullable=False)
	temperature = db.Column(db.Float, nullable=False)
	notes = db.Column(db.Text, nullable=True)
	creation_date = db.Column(db.DateTime, nullable=False)
	# Define a foreign key column referencing the 'patient' table
	patient_id = db.Column(db.Integer, ForeignKey('patient.id'), nullable=False)

class Patient(db.Model):
	__tablename__ = 'patient'
	id = db.Column(db.Integer, primary_key=True)
	first_name = db.Column(db.String(20), nullable=False)
	last_name = db.Column(db.String(20), nullable=False)
	# email = db.Column(db.String(120), unique=True, nullable=False)
	email = db.Column(db.String(120), nullable=False)
	phone = db.Column(db.String(20), nullable=False)
	creation_date = db.Column(db.DateTime, nullable=False)

	health_data = relationship('HealthData', backref='patient', cascade='all, delete-orphan')

class User(db.Model):
	__tablename__ = 'user'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), unique=True, nullable=False)
	password = db.Column(db.String(60), nullable=False)
	role = db.Column(db.Integer)
	creationDate = db.Column(db.DateTime, nullable=False)
	email = db.Column(db.String(120), unique=True, nullable=False)
	recovery_token = db.Column(db.String(128))
	token_expiration = db.Column(db.DateTime)
	validated = db.Column(db.Boolean, default=False)

	def __repr__(self):
		return f'{self.username}:{self.password} ({Role(self.role)})'

	def __init__(self, username: str, password: str, creation_date: DateTime, email: str):
		self.username = username
		# self.password = generate_password_hash(password, method='sha256')
		self.password = generate_password_hash(password, method='scrypt')
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


@dataclass
class BrowserInfo:
	family: str
	version: str


class Session(db.Model):
	__tablename__ = 'sessions'
	id = db.Column(db.Integer, primary_key=True, autoincrement=True)
	start = db.Column(db.DateTime, nullable=False)
	end = db.Column(db.DateTime, nullable=True)
	client_ip = db.Column(db.String(15), nullable=False)
	browser_family = db.Column(db.String(20), nullable=False)
	browser_version = db.Column(db.String(10), nullable=False)
	login_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

	def __repr__(self):
		user: User = User.query.get(self.login_id)
		if not self.end:
			return f'{user.username} connecté depuis: {self.start}'
		else:
			return f'{user.username} déconnecté à: {self.end}'

	@property
	def username(self) -> str:
		return User.query.get(self.login_id).username

	def __init__(self, login_id: int, start: DateTime, client_ip: str, browser_family: str, browser_version: str):
		self.login_id = login_id
		self.start = start
		self.end = None
		self.client_ip = client_ip
		self.browser_family = browser_family
		self.browser_version = browser_version
