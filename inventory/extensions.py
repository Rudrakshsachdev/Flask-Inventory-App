from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

db = SQLAlchemy()  # Initialize the SQLAlchemy instance
login_manager = LoginManager() # Initialize the LoginManager instance
mail = Mail() # Initialize the Mail instance


