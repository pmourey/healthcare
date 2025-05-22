from __future__ import annotations

import re
from datetime import datetime
from functools import wraps
from typing import Match

from dateutil.relativedelta import relativedelta
from flask import flash
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


def validate_password_complexity_old(password):
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


def validate_password_complexity(password):
	"""
	Validates password against security requirements for healthcare systems.
	Returns (bool, str) tuple - (is_valid, error_message)
	"""
	# # Liste des règles pour affichage
	# password_rules = [
	#     "Au moins 10 caractères",
	#     "Au moins une lettre majuscule",
	#     "Au moins une lettre minuscule",
	#     "Au moins un chiffre",
	#     "Au moins un caractère spécial (!@#$%^&*(),.?\":{}|<>)",
	#     "Pas de motifs communs (password, 123456, qwerty, admin)",
	#     "Pas de caractères répétés plus de deux fois"
	# ]

	# # Afficher les règles avec flash
	# flash("Règles de sécurité du mot de passe:", "info")
	# for rule in password_rules:
	#     flash(f"• {rule}", "info")

	# Validation
	if len(password) < 10:
		# flash("Erreur: Le mot de passe doit contenir au moins 10 caractères", "error")
		return False, "Password must be at least 10 characters long"

	if not re.search(r'[A-Z]', password):
		# flash("Erreur: Le mot de passe doit contenir au moins une majuscule", "error")
		return False, "Password must contain at least one uppercase letter"

	if not re.search(r'[a-z]', password):
		# flash("Erreur: Le mot de passe doit contenir au moins une minuscule", "error")
		return False, "Password must contain at least one lowercase letter"

	if not re.search(r'\d', password):
		# flash("Erreur: Le mot de passe doit contenir au moins un chiffre", "error")
		return False, "Password must contain at least one number"

	if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
		# flash("Erreur: Le mot de passe doit contenir au moins un caractère spécial", "error")
		return False, "Password must contain at least one special character"

	common_patterns = ['password', '123456', 'qwerty', 'admin']
	if any(pattern in password.lower() for pattern in common_patterns):
		# flash("Erreur: Le mot de passe contient des motifs interdits", "error")
		return False, "Password contains common patterns that are not allowed"

	if re.search(r'(.)\1{2,}', password):
		# flash("Erreur: Le mot de passe ne peut pas contenir de caractères répétés plus de deux fois", "error")
		return False, "Password cannot contain characters repeating more than twice"

	flash("Le mot de passe respecte toutes les règles de sécurité", "success")
	return True, "Password meets security requirements"


def end_other_sessions(user_id: int, current_session_id: int = None) -> None:
	"""
	Termine toutes les autres sessions actives d'un utilisateur
	excepté la session courante si spécifiée
	"""
	query = Session.query.filter(Session.login_id == user_id, Session.end.is_(None)) # Sessions actives uniquement

	# Si une session courante est spécifiée, on l'exclut
	if current_session_id:
		query = query.filter(Session.id != current_session_id)

	# Met à jour toutes les autres sessions avec une date de fin
	query.update({Session.end: datetime.now()}, synchronize_session=False)

	db.session.commit()
