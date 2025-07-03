from flask import Flask
from .extensions import db, login_manager, mail # Import the SQLAlchemy instance
from .routes import main # Import the main blueprint from routes
from .auth_routes import auth # Import the auth blueprint for authentication routes
from .models import User # Import the User model for user authentication
import os



# Function to create and configure the Flask application and initialize the database
def create_app():
    app = Flask(__name__) 

    # Configuration settings for the flask application
    app.config['SECRET_KEY'] = 'YOUR-SECRET-KEY'
    app.config['SECURITY_PASSWORD_SALT'] = 'YOUR-PASSWORD-SALT' # This is used for password hashing and token generation
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db' # This line sets the database URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Disable track modifications to save resources

    # Configuration settings for Flask-Mail
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'YOUR-EMAIL-ID'
    app.config['MAIL_PASSWORD'] = 'YOUR-EMAIL-PASSWORD'


    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'uploads') # Define the upload folder path
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # configurations for the profile image
    PROFILE_IMG_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'profiles')
    app.config['PROFILE_IMG_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'profiles')
    os.makedirs(app.config['PROFILE_IMG_FOLDER'], exist_ok = True) # Create the profile image folder if it doesn't exist
    
    
    # Configurations for the product image upload
     
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 mb limit for file uploads
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'} 



    db.init_app(app) # Initialize the SQLAlchemy instance with the Flask app
    login_manager.init_app(app) # Initialize the login manager with the flask app
    mail.init_app(app) # Initialize the mail instance with the Flask app

    login_manager.login_view = 'auth.login' # Setting the login view for the login manager



    app.register_blueprint(main) # Register the main blueprint
    app.register_blueprint(auth) # Register the auth blueprint

    return app # Return the Flask application instance

# Function to load the user by user_id for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

