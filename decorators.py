""" decorators """
from functools import wraps
from flask import session, render_template, request

from Controller import get_user_by_id


def is_connected(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        # app.logger.debug(f'is_connected: session = {session}')
        if 'login_id' not in session:
            error = 'Restricted access! Please authenticate.'
            return render_template('login.html', error=error)
            # return redirect(url_for('login.html'))  # Remplacez 'login.html' par l'URL de votre page de connexion
        return func(*args, **kwargs)

    return wrapper

def is_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = get_user_by_id(session['login_id'])
        if not user.is_admin:
            error = 'Insufficient privileges for this operation! Please contact administrator...'
            return render_template('login.html', error=error)
        return func(*args, **kwargs)
    return wrapper

def get_client_ip():
    # Check headers in order of reliability
    if request.headers.getlist("X-Forwarded-For"):
        client_ip = request.headers.getlist("X-Forwarded-For")[0]
    elif request.headers.get("X-Real-IP"):
        client_ip = request.headers.get("X-Real-IP")
    elif request.headers.get("CF-Connecting-IP"):    # Cloudflare
        client_ip = request.headers.get("CF-Connecting-IP")
    else:
        client_ip = request.remote_addr
    return client_ip

