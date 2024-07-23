from models import db, User, Vendor, Component, Vulnerability, Token
from dotenv import load_dotenv
import os, uuid
from app import app
from werkzeug.security import generate_password_hash
from sqlalchemy import inspect


load_dotenv()

def check_for_database():
    with app.app_context():
        inspector = inspect(db.engine)

        if 'users' not in inspector.get_table_names():
            print("Initalizing the database.")
            initialize_database()
        else:
            print("Database already initialized.")

def initialize_database():
    with app.app_context():
        db.create_all()

        # Assuming test_company.id is populated after commit
        default_user = User(name="Default User", email="admin@local.com", password=generate_password_hash(os.getenv("ADMIN_PASS"), "pbkdf2"), confirmed=True, role="Super Admin", public_id=str(uuid.uuid4()))
        db.session.add(default_user)
        db.session.commit()

if __name__ == '__main__':
    check_for_database()
