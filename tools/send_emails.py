import smtplib
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List


def send_email_old(subject: str, body: str, sender_email: str, recipient_email: str, bcc_recipients: List[str], smtp_server: str, smtp_port: int, username: str, password: str, author: str) -> bool:
    # Create the email message
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = f'"{author}" {sender_email}'
    msg['To'] = recipient_email
    msg['Bcc'] = bcc_recipients  # Set the Bcc header with a comma-separated list of BCC recipients

    msg.set_content(body)
    # Format the message body as HTML with hyperlinks
    msg.add_alternative(body, subtype='html')

    try:
        # Connect to the SMTP server
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            # server.starttls()  # Use this for TLS connections
            server.login(username, password)

            # Send the email
            server.send_message(msg)
        print(f'Email sent successfully to {recipient_email}!')
        return True
    except Exception as e:
        print(f'Error sending the email: {e}')
        return False

def send_email(subject: str, body: any, sender_email: str, recipient_email: str,
               bcc_recipients: List[str], smtp_server: str, smtp_port: int,
               username: str, password: str, author: str) -> bool:
    try:
        # Si body est déjà un objet MIMEMultipart, l'utiliser directement
        if isinstance(body, MIMEMultipart):
            msg = body
            msg['Subject'] = subject
            msg['From'] = f'"{author}" <{sender_email}>'
            msg['To'] = recipient_email
            if bcc_recipients:
                msg['Bcc'] = ', '.join(bcc_recipients)
        else:
            # Créer un nouveau message si body est une chaîne
            msg = MIMEMultipart('related')
            msg['Subject'] = subject
            msg['From'] = f'"{author}" <{sender_email}>'
            msg['To'] = recipient_email
            if bcc_recipients:
                msg['Bcc'] = ', '.join(bcc_recipients)

            # Ajouter le contenu
            msg_text = MIMEText(body, 'html')
            msg.attach(msg_text)

        # Connexion et envoi
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(username, password)
            server.send_message(msg)

        print(f'Email sent successfully to {recipient_email}!')
        return True

    except Exception as e:
        print(f'Error sending email: {e}')
        return False
