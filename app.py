"""
Copyright © 2024 Philippe Mourey

This script provides CRUD features inside a Flask application to offer a tool for tennis clubs to help build teams and manage player availability

"""
from __future__ import annotations

import base64
import os
import re
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import Flask, request, flash, url_for, redirect, render_template, session, send_file, jsonify
from flask_wtf.csrf import CSRFProtect  # Import correct pour CSRFProtect

from flask_login import LoginManager, logout_user
from pytz import timezone
from sqlalchemy import desc
from werkzeug.security import generate_password_hash, check_password_hash

from Controller import get_user_by_id, check, send_confirmation_email, send_password_recovery_email, get_session_by_login, create_user, validate_password_complexity
from Model import User, db, Session, Patient, HealthData

import secrets
from itsdangerous import URLSafeSerializer, Serializer
from user_agents import parse
from user_agents.parsers import UserAgent

from logging import basicConfig, DEBUG
import locale
from datetime import datetime, timedelta

from decorators import is_connected, is_admin
from tools.send_emails import send_email


app = Flask(__name__, static_folder='static', static_url_path='/static')
# Set the secret key
app.secret_key = secrets.token_bytes(32).hex()
# Create serializer
app.serializer = URLSafeSerializer(app.secret_key)
# Config
app.config.from_object('config.Config')
# Initialize extensions
db.init_app(app)
# migrate.init_app(app, db)

# Locale settings
locale.setlocale(locale.LC_TIME, 'fr_FR')
basicConfig(level=DEBUG)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

csrf = CSRFProtect(app)


# Add the filter to the Jinja environment


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


def get_client_ip():
	# Check headers in order of reliability
	if request.headers.getlist("X-Forwarded-For"):
		client_ip = request.headers.getlist("X-Forwarded-For")[0]
	elif request.headers.get("X-Real-IP"):
		client_ip = request.headers.get("X-Real-IP")
	elif request.headers.get("CF-Connecting-IP"):  # Cloudflare
		client_ip = request.headers.get("CF-Connecting-IP")
	else:
		client_ip = request.remote_addr
	return client_ip

@csrf.exempt
@app.route('/')
def welcome():
	user = None
	token = None
	if 'login_id' in session:
		user = get_user_by_id(session['login_id'])
		# Générer un jeton de récupération de mot de passe
		s = Serializer(app.config['SECRET_KEY'])
		token = s.dumps({'user_id': user.id})
		# Mettez à jour le modèle d'utilisateur avec le jeton et le délai d'expiration
		# user.recovery_token = generate_password_hash(token, method='sha256')
		user.recovery_token = generate_password_hash(token)
		user.token_expiration = datetime.now() + timedelta(hours=24)
		db.session.commit()
	else:
		# client_ip = request.remote_addr
		client_ip = get_client_ip()
		user_agent_string = request.headers.get('User-Agent')
		user_agent: UserAgent = parse(user_agent_string)
		browser_info = f"Family = {user_agent.browser.family}, Version = {user_agent.browser.version_string}"
		app.logger.debug(f"Client IP: {client_ip}, Browser: ({browser_info})")
	return render_template('index.html', session=session, user=user, token=token)

@csrf.exempt
@app.route("/register", methods=['GET', 'POST'])
def register():
	# Logique d'enregistrement ici
	error = None
	if request.method == 'POST':
		username: str = request.form['username']
		email: str = request.form['email']
		password: str = request.form['password']
		confirm_password: str = request.form['confirm_password']
		if confirm_password != password:
			# flash('Incorrect login credentials.', 'error')
			error = 'Password does not match! Please try again.'
		else:
			existing_user: User = User.query.filter_by(username=username).first()
			existing_email: User = User.query.filter_by(email=email).first()
			if existing_user:
				error = f'user {existing_user.username} already exists! Please choose another name.'
			elif existing_email:
				error = f'email {existing_email.email} already exists! Please choose another email.'
			elif not check(app.config['REGEX'], email):
				error = f'email {email} is invalid! Please check syntax.'
			else:
				try:
					user = create_user(username, password, email)  # Add code to save user to database
					# user = User(username=username, password=password, creation_date=datetime.now(), email=email)
					# logging.warning("See this message in Flask Debug Toolbar!")
					db.session.add(user)
					db.session.commit()
					s = Serializer(app.config['SECRET_KEY'])
					# s = URLSafeSerializer('SECRET_KEY')
					token = s.dumps({'user_id': user.id})

					# Mettez à jour le modèle d'utilisateur avec le jeton et le délai d'expiration
					# user.recovery_token = generate_password_hash(token, method='sha256')
					user.recovery_token = generate_password_hash(token)
					user.token_expiration = datetime.now() + timedelta(minutes=10)
					# app.logger.debug(f'time zone info: {user.token_expiration.tzinfo}')

					db.session.commit()

					# Envoyer un e-mail de confirmation d'inscription

					flash('Un e-mail de demande de confirmation d\'inscription a été envoyé!', 'success')
					confirm_link = url_for('validate_email', token=token, _external=True)
					send_confirmation_email(app=app, confirm_link=confirm_link, user=user, author=app.config['GMAIL_FULLNAME'])
					return redirect(url_for('register'))
				except ValueError as e:
					# Handle the error appropriately (e.g., return to form with error message)
					error = str(e)
	return render_template('register.html', error=error)

@csrf.exempt
@app.route("/login", methods=['GET', 'POST'])
def login():
	# Logique de connexion ici
	error = None
	if request.method == 'POST':
		user = User.query.filter_by(username=request.form['username']).first()
		app.logger.debug(f'user = {user} - clear pwd = {request.form["password"]}')
		if user and check_password_hash(user.password, password=request.form['password']):
			if user.validated:
				session['login_id'] = user.id
				app.logger.debug(f'user (login) = {user.username} - id = {user.id} - session: {session}')
				# client_ip = request.remote_addr
				client_ip = get_client_ip()
				user_agent_string = request.headers.get('User-Agent')
				user_agent: UserAgent = parse(user_agent_string)
				sess = Session(login_id=user.id, start=datetime.now(), client_ip=client_ip, browser_family=user_agent.browser.family, browser_version=user_agent.browser.version_string)
				db.session.add(sess)
				db.session.commit()
				return redirect(url_for('welcome'))
			else:
				error = 'Your account is not yet validated! Please check your email for the confirmation link.'
				return render_template('login.html', error=error)
		else:
			error = 'Incorrect login credentials. Please try again.'
			return render_template('login.html', error=error)
	return render_template('login.html', error=error)

@csrf.exempt
@app.route("/change_password", methods=['GET', 'POST'])
@is_connected
def change_password():
	error = None
	if request.method == 'POST':
		user = get_user_by_id(session['login_id'])
		new_password: str = request.form["new_password"]
		confirm_new_password: str = request.form["confirm_new_password"]
		app.logger.debug(f'user (change pwd) = {user.username} - new pwd = {new_password} - confirm_new_pwd = {confirm_new_password}')
		if new_password == confirm_new_password:
			try:
				is_valid, error_message = validate_password_complexity(new_password)
				if not is_valid:
					raise ValueError(error_message)
				user.password = generate_password_hash(new_password, method='sha256')
				db.session.add(user)
				db.session.commit()
				flash('Password was successfully changed!')
				return redirect(url_for('welcome'))
			except ValueError as e:
				# Handle the error appropriately (e.g., return to form with error message)
				error = str(e)
		else:
			error = 'Passwords does not match! Please try again.'
	return render_template('reset_password.html', error=error)

@csrf.exempt
@app.route('/request_reset_password', methods=['GET', 'POST'])
def request_reset_password():
	if request.method == 'POST':
		email = request.form.get('email')
		user = User.query.filter_by(email=email.lower()).first()
		if user:
			# Générer un jeton de récupération de mot de passe
			s = Serializer(app.config['SECRET_KEY'])
			token = s.dumps({'user_id': user.id})

			# Mettez à jour le modèle d'utilisateur avec le jeton et le délai d'expiration
			# user.recovery_token = generate_password_hash(token, method='sha256')
			user.recovery_token = generate_password_hash(token)
			user.token_expiration = datetime.now() + timedelta(minutes=10)

			db.session.commit()

			# Envoyer le lien de récupération par e-mail (vous devez implémenter cette partie)
			# Vous pouvez utiliser un package comme Flask-Mail pour envoyer des e-mails.

			flash('Un e-mail de récupération de mot de passe a été envoyé.', 'success')
			reset_link = url_for('reset_password', token=token, _external=True)
			send_password_recovery_email(app=app, reset_link=reset_link, user=user, author=app.config['GMAIL_FULLNAME'])
			return redirect(url_for('login'))

		flash('Aucun utilisateur trouvé avec cet e-mail.', 'error')

	return render_template('request_reset_password.html')

@app.route('/validate_email/<token>', methods=['GET', 'POST'])
def validate_email(token):
	error: str = None
	# Vérifier si le jeton est valide
	s = Serializer(app.config['SECRET_KEY'])
	try:
		data = s.loads(token)
		user = User.query.get_or_404(data['user_id'])
		# Calculate the time difference
		remaining_minutes = int((user.token_expiration - datetime.now()).total_seconds() / 60)
		app.logger.debug(f'remaining minutes: {remaining_minutes}')
		if remaining_minutes <= 0:
			raise Exception
	except Exception as e:
		app.logger.debug(e)
		flash('Le lien de confirmation d\'inscription est invalide ou a expiré.')
		user = User.query.get_or_404(data.get('user_id'))
		if user:
			db.session.delete(user)
			db.session.commit()
		return redirect(url_for('login'))

	user = User.query.get(data['user_id'])

	# Mettre à jour le champ de confirmation d'inscription de l'utilisateur
	user.validated = True

	# Réinitialiser le champ de récupération de mot de passe
	user.recovery_token = None
	user.token_expiration = None

	db.session.commit()

	flash('Votre compte a été confirmé avec succès.', 'success')
	return redirect(url_for('login'))

@csrf.exempt
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
	error: str = None
	# Vérifier si le jeton est valide
	s = Serializer(app.config['SECRET_KEY'])
	try:
		data = s.loads(token)
		user = User.query.get_or_404(data['user_id'])
		# Calculate the time difference
		remaining_minutes = int((user.token_expiration - datetime.now()).total_seconds() / 60)
		app.logger.debug(f'remaining minutes: {remaining_minutes}')
		if remaining_minutes <= 0:
			raise Exception
	except:
		flash('Le lien de réinitialisation de mot de passe est invalide ou a expiré.')
		return redirect(url_for('login'))

	user = User.query.get(data['user_id'])
	app.logger.debug(f'reset password user {user.username} - data = {data} \n - token = {token}')

	if request.method == 'POST':
		new_password = request.form.get('new_password')
		confirm_new_password = request.form.get('confirm_new_password')

		if new_password == confirm_new_password:
			try:
				is_valid, error_message = validate_password_complexity(new_password)
				if not is_valid:
					raise ValueError(error_message)
				# Mettre à jour le mot de passe de l'utilisateur
				# user.password = generate_password_hash(new_password, method='sha256')
				user.password = generate_password_hash(new_password)

				# Réinitialiser le champ de récupération de mot de passe
				user.recovery_token = None
				user.token_expiration = None

				db.session.commit()

				flash('Le mot de passe a été réinitialisé avec succès.', 'success')
				return redirect(url_for('login'))
			except ValueError as e:
				# Handle the error appropriately (e.g., return to form with error message)
				error = str(e)
		else:
			error = 'Les mots de passe ne correspondent pas.'

	return render_template('reset_password.html', error=error, token=token)


@app.route("/logout")
@is_connected
def logout():
	user = get_user_by_id(session['login_id'])
	sess = get_session_by_login(username=user.username)
	if sess is not None:
		sess.end = datetime.now()
		db.session.commit()
	logout_user()
	# remove the username from the session if it's there
	session.pop('login_id', None)
	flash('You have been logged out.', 'success')
	return redirect(url_for('login'))


@app.route('/accounts')
@is_connected
@is_admin
def show_accounts():
	user = get_user_by_id(session['login_id'])
	# Reverse order query
	accounts = User.query.order_by(desc(User.id)).all()
	return render_template('accounts.html', accounts=accounts, user=user)


@app.route('/update_account/<int:id>', methods=['GET', 'POST'])
@is_connected
@is_admin
def update_account(id):
	user: User = User.query.get_or_404(id)
	# app.logger.debug(f'User debug: {user}')
	if request.method == 'POST':
		roles = ['Administrateur', 'Editeur', 'Lecteur']
		user.role = roles.index(request.form.get('role'))
		db.session.commit()
		flash('Record was successfully updated')
		return redirect(url_for('show_accounts'))
	else:
		return render_template('update_account.html', user=user)


@app.route('/sessions')
@is_connected
@is_admin
def show_sessions():
	# Reverse order query
	sessions = Session.query.filter(Session.end.is_(None)).order_by(desc(Session.id)).all()
	return render_template('sessions.html', sessions=sessions)

@csrf.exempt
@app.route('/new_patient/', methods=['GET', 'POST'])
@is_connected
def new_patient():
	app.logger.debug(f'request.method: {request.method}')
	if request.method == 'POST':
		first_name = request.form['firstname']
		last_name = request.form['lastname']
		email = request.form['email']
		phone = request.form['phone']
		if not (first_name and last_name and email and phone):
			flash('Please enter all the fields', 'error')
		else:
			# check if patient already exists by first_name and last_name
			patient = Patient.query.filter_by(first_name=first_name.capitalize(), last_name=last_name.capitalize()).first()
			if patient:
				flash(f'Patient {first_name} {last_name} already exists!', 'error')
			else:
				# patient = Patient(first_name=first_name.capitalize(), last_name=last_name.capitalize(), email=email, phone=phone, creation_date=datetime.now())
				user = get_user_by_id(session['login_id'])
				patient = Patient(first_name=first_name.capitalize(), last_name=last_name.capitalize(), email=email, phone=phone, creation_date=datetime.now(), user_id=user.id)
				# logging.warning("See this message in Flask Debug Toolbar!")
				db.session.add(patient)
				db.session.commit()
				flash('Record was successfully added')
				return redirect(url_for('new_patient'))

	return render_template('new_patient.html')

@csrf.exempt
@app.route('/new_health_data/<int:id>', methods=['GET', 'POST'])
@is_connected
def new_health_data(id: int):
	# app.logger.debug(f'request.form: {request.form}')
	patient = Patient.query.get_or_404(id)
	# app.logger.debug(f'patient: {patient}')
	if request.method == 'POST':
		weight = request.form['weight']
		height = request.form['height']
		heart_rate = request.form['heart_rate']
		blood_pressure_sys = int(request.form['blood_pressure_sys'])
		blood_pressure_dia = int(request.form['blood_pressure_dia'])
		temperature = request.form['temperature']
		notes = request.form['notes']
		if not (weight and height and heart_rate and blood_pressure_sys and blood_pressure_dia and temperature):
			flash('Please enter all the fields', 'error')
		else:
			health_data = HealthData(weight=weight, height=height, heart_rate=heart_rate, blood_pressure_sys=blood_pressure_sys, blood_pressure_dia=blood_pressure_dia, temperature=temperature, notes=notes, creation_date=datetime.now(), patient_id=id)
			# logging.warning("See this message in Flask Debug Toolbar!")
			db.session.add(health_data)
			db.session.commit()
			flash('Record was successfully added')
	return render_template('new_health_data.html', patient=patient)


@app.route('/show_health_data/<int:id>')
@is_connected
def show_health_data(id: int):
	patient = Patient.query.get_or_404(id)
	return render_template('patient_health_data.html', patient=patient)


@app.route('/show_patients')
@is_connected
def show_patients():
	user = get_user_by_id(session['login_id'])
	patients = Patient.query.filter_by(user_id=user.id).order_by(desc(Patient.id)).all()
	# patients = Patient.query.order_by(desc(Patient.id)).all()
	app.logger.debug(f'patients: {patients}')
	return render_template('patients.html', patients=patients, user=user)


@csrf.exempt
@app.route('/patient/<int:patient_id>/send-reports', methods=['POST'])
@is_connected
def send_health_reports(patient_id):
	selected_reports = request.form.getlist('selected_reports')
	patient = Patient.query.get_or_404(patient_id)

	if not selected_reports:
		flash('Veuillez sélectionner au moins un rapport', 'error')
		return redirect(url_for('show_health_data', id=patient_id))

	user: User = get_user_by_id(session['login_id'])
	# Fetch the selected reports
	reports = HealthData.query.filter(HealthData.id.in_(selected_reports)).all()
	if send_email(subject=f'Rapports de santé - {patient.first_name} {patient.last_name}',
			   body=render_template('email/health_report.html', patient=patient, reports=reports),
			   sender_email=user.email,
			   recipient_email=patient.email,
			   bcc_recipients=[],
			   smtp_server=app.config['SMTP_SERVER'],
			   smtp_port=app.config['SMTP_PORT'],
			   username=app.config['GMAIL_USER'],
			   password=app.config['GMAIL_APP_PWD'],
			   author=app.config['GMAIL_FULLNAME']):

		flash('Rapports envoyés avec succès', 'success')
	else:
		flash(f'Erreur lors de l\'envoi des rapports: {str(e)}', 'error')

	return redirect(url_for('show_health_data', id=patient.id))



@app.route('/patient/report/<int:id>')
@is_connected
def patient_report(id):
	patient = Patient.query.get_or_404(id)
	health_data = HealthData.query.filter_by(patient_id=id).order_by(HealthData.creation_date).all()

	dates = [data.creation_date.strftime('%d/%m/%Y') for data in health_data]
	weights = [data.weight for data in health_data]
	blood_pressure_sys = [data.blood_pressure_sys for data in health_data]
	blood_pressure_dia = [data.blood_pressure_dia for data in health_data]

	return render_template('patient_report.html', patient=patient, today=datetime.now(), dates=dates, weights=weights, blood_pressure_sys=blood_pressure_sys, blood_pressure_dia=blood_pressure_dia)


@csrf.exempt
@app.route('/send_report_email', methods=['POST'])
@is_connected
def send_report_email():
	try:
		data = request.json
		email = data['email']
		first_name = data['firstName']
		last_name = data['lastName']
		chart_image = data['chartImage']

		# Extraire les données de l'image
		image_data = re.sub('^data:image/.+;base64,', '', chart_image)
		image_bytes = base64.b64decode(image_data)

		# Créer le message multipart
		msg = MIMEMultipart('related')

		# Corps HTML
		html_content = f"""
        <html>
        <body>
            <h2>Rapport médical</h2>
            <p>Bonjour {first_name} {last_name},</p>
            <p>Veuillez trouver ci-joint votre rapport médical avec le graphique de votre évolution.</p>
            <p>Voici votre graphique d'évolution :</p>
            <img src="cid:chart_image" alt="Graphique d'évolution" style="max-width: 100%;">
            <br>
            <p>Cordialement,<br>
            Votre équipe médicale</p>
        </body>
        </html>
        """

		# Ajouter le corps HTML
		msg_html = MIMEText(html_content, 'html')
		msg.attach(msg_html)

		# Ajouter l'image
		img = MIMEImage(image_bytes)
		img.add_header('Content-ID', '<chart_image>')
		img.add_header('Content-Disposition', 'inline', filename='evolution_medicale.png')
		msg.attach(img)

		# Envoyer l'email
		success = send_email(subject=f'Rapport médical - {first_name} {last_name}', body=msg,  # Passer directement l'objet MIMEMultipart
			sender_email=app.config['GMAIL_USER'], recipient_email=email, bcc_recipients=[], smtp_server=app.config['SMTP_SERVER'], smtp_port=app.config['SMTP_PORT'], username=app.config['GMAIL_USER'], password=app.config['GMAIL_APP_PWD'], author="Service Médical")

		if success:
			return jsonify({'success': True})
		else:
			return jsonify({'success': False, 'error': 'Échec de l\'envoi de l\'email'})

	except Exception as e:
		return jsonify({'success': False, 'error': str(e)})


@app.before_request
def create_tables():
	db.create_all()


@app.template_filter('format_paris_time')
def format_paris_time(utc_dt):
	paris_tz = timezone('Europe/Paris')
	paris_time = utc_dt.astimezone(paris_tz)
	return paris_time.strftime('%A %d %B %Y à %Hh%M')


if __name__ == '__main__':
	app.run()
