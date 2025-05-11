from __future__ import annotations

import re
from datetime import datetime
from functools import wraps
from typing import Match

from dateutil.relativedelta import relativedelta
from werkzeug.security import generate_password_hash

from Model import User, db, Session
from tools.send_emails import send_email

""" SQL Alchemy requests """


def get_user_by_id(user_id: int) -> User:
	# Effectue la requête pour récupérer un utilisateur par nom d'utilisateur et mot de passe
	return User.query.filter_by(id=user_id).first()


def get_session_by_login(username: str) -> Session:
	# Récupère la session la plus récente
	user: User = User.query.filter_by(username=username).first()
	return Session.query.filter_by(login_id=user.id).order_by(Session.start.desc()).first()


""" Utilities """


def check(regex: str, email: str) -> Match[str] | None:
	return re.fullmatch(regex, email)


""" Back-end features """


def send_confirmation_email(app, confirm_link: str, user: User, author: str) -> bool:
	subject: str = f"Confirmation de l'inscription ({app.config['NAME']})"
	body = f'''Bonjour {user.username},<br>
    <br>Une demande de création de compte a été effectuée sur l'application "{app.config['NAME']}"</br>
    <br>
    <br>Veuillez clicker <a href={confirm_link}>ICI</a> pour confirmer votre inscription, svp.<br>
    <br>
    <br>Si vous avez aimé l'application, n'hésitez pas à me le faire savoir ou à la partager à vos amis ou collègues.<br>
    <br>En vous souhaitant une bonne journée.<br>
    <br>
    Cordialement,<br>
    {author}.<br><br>'''
	return send_email(subject=subject, body=body, sender_email=app.config['GMAIL_USER'], recipient_email=f'"{user.username}"<{user.email}>', bcc_recipients=[app.config['GMAIL_USER']], smtp_server=app.config['SMTP_SERVER'], smtp_port=app.config['SMTP_PORT'], username=app.config['GMAIL_USER'], password=app.config['GMAIL_APP_PWD'], author=app.config['GMAIL_FULLNAME'], )


def send_password_recovery_email(app, reset_link: str, user: User, author: str) -> bool:
	subject: str = f'Demande de réinitialisation de mot de passe ({app.config['NAME']})'
	body = f'''Bonjour {user.username},<br>
    <br>Vous êtes utilisateur de l'application Flask "{app.config['NAME']}", et une demande de réinitialisation de mot de passe a été effectuée</br>
    <br>Veuillez clicker sur le lien ci-dessous pour lancer le formulaire de réinitialisation.<br>
    <br>{reset_link}<br>
    <br>Si vous avez aimé l'application, n'hésitez pas à me le faire savoir ou à la partager à vos amis ou collègues.<br>
    <br>En vous souhaitant une bonne journée.<br>
    <br>
    Cordialement,<br>
    {author}.<br>'''
	return send_email(subject=subject, body=body, sender_email=app.config['GMAIL_USER'], recipient_email=f'"{user.username}"<{user.email}>', bcc_recipients=[], smtp_server=app.config['SMTP_SERVER'], smtp_port=app.config['SMTP_PORT'], username=app.config['GMAIL_USER'], password=app.config['GMAIL_APP_PWD'], author=app.config['GMAIL_FULLNAME'], )


""" Password policy check """

import re
from datetime import datetime


def validate_password_complexity(password):
	"""
    Validates password against security requirements for healthcare systems.
    Returns (bool, str) tuple - (is_valid, error_message)
    """
	if len(password) < 10:
		return False, "Password must be at least 10 characters long"

	# Check for at least one uppercase letter
	if not re.search(r'[A-Z]', password):
		return False, "Password must contain at least one uppercase letter"

	# Check for at least one lowercase letter
	if not re.search(r'[a-z]', password):
		return False, "Password must contain at least one lowercase letter"

	# Check for at least one number
	if not re.search(r'\d', password):
		return False, "Password must contain at least one number"

	# Check for at least one special character
	if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
		return False, "Password must contain at least one special character"

	# Check for common patterns to avoid
	common_patterns = ['password', '123456', 'qwerty', 'admin']
	if any(pattern in password.lower() for pattern in common_patterns):
		return False, "Password contains common patterns that are not allowed"

	# Check for repeating characters (more than 2 times)
	if re.search(r'(.)\1{2,}', password):
		return False, "Password cannot contain characters repeating more than twice"

	return True, "Password meets security requirements"


def create_user(username, password, email):
	try:
		# Validate password complexity
		is_valid, error_message = validate_password_complexity(password)
		if not is_valid:
			raise ValueError(error_message)

		# If validation passes, create the user
		# It's recommended to hash the password before storing
		hashed_password = generate_password_hash(password)

		user = User(username=username, password=hashed_password, creation_date=datetime.now(), email=email)

		return user

	except ValueError as e:
		raise ValueError(f"Password validation failed: {str(e)}")
