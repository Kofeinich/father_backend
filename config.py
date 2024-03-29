from envparse import env

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

FROM_EMAIL = env.str("FROM_EMAIL")
TO_EMAIL = env.str("TO_EMAIL")
MAIL_PASSWORD = env.str("MAIL_PASSWORD")
BODY_TEMPLATE = '''New mail
Name: %s
Email: %s
Phone: %s
Text: %s
'''

DB_URL = 'sqlite://db.sqlite3'
