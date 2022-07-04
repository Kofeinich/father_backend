import smtplib

# Import the email modules we'll need
from email.mime.text import MIMEText

import config


def gmail_send_message(subj, body):
    msg = MIMEText(body, "plain")

    # me == the sender's email address
    # you == the recipient's email address
    msg['Subject'] = subj
    msg['From'] = config.FROM_EMAIL
    msg['To'] = config.TO_EMAIL

    server = smtplib.SMTP_SSL('smtp.mail.ru', 465)
    server.login(config.FROM_EMAIL, config.MAIL_PASSWORD)
    text = msg.as_string()
    server.sendmail(config.FROM_EMAIL, config.TO_EMAIL, text)
    server.quit()
