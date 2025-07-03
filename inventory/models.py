from .extensions import db # Import the database instance
from datetime import datetime
from flask_login import UserMixin # Import UserMixin for user authentication

from itsdangerous import URLSafeTimedSerializer # Import URLSafeTimedSerializer for generating secure tokens
from flask import current_app # Import current_app to access the Flask application context

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100), nullable = False)
    email = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(200), nullable = False)
    created_at = db.Column(db.DateTime, default = datetime.utcnow)
    profile_image = db.Column(db.String(200), nullable = True)
    role = db.Column(db.String(50), default = 'user') # role of the user (e.g., admin, user)
    is_admin_verified = db.Column(db.Boolean, default = False) # flag to check if the user is admin verified
    


# Product model to represent products in the inventory
class Product(db.Model):
    id = db.Column(db.Integer, primary_key = True) # Unique identifier for each product
    name = db.Column(db.String(100), nullable = False) # Name of the product
    description = db.Column(db.String(200), nullable = True) # Description of the product
    price = db.Column(db.Float, nullable = False) # Price of the product
    quantity = db.Column(db.Integer, nullable = False) # Quantity of the product in the inventory
    image = db.Column(db.String(200), nullable = True) # Url or path to the product image
    created_at = db.Column(db.DateTime, default = datetime.utcnow) # timestamp when the product was created

    def __repr__(self):
        return f'<product {self.name}>'

# Order model to represent a custom order in the inventory
class Order(db.Model):
    id = db.Column(db.Integer, primary_key = True) # Unique idetifier for each order
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable = False) # Foreign key to the product
    customer_name = db.Column(db.String(100), nullable = False) # Name of the customer who placed the order
    quantity = db.Column(db.Integer, nullable = False) # Quantity of the product ordered
    status = db.Column(db.String(50), nullable = False, default = 'Pending') # Status of the order (e.g., Pending, Completed, Cancelled)
    order_date = db.Column(db.DateTime, default = datetime.utcnow) # Timestamp when the order was placed

    # Relationship: allow access to the product details from the order
    product = db.relationship('Product', backref = 'orders', lazy = True)

    def __repr__(self):
        return f'<Order {self.id} for {self.customer_name}>' # Representation of the order

# Function to generate a secure token for password reset   
def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY']) # Create a serializer with the secret key
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT']) # Generate a token for the email with a salt

# Function to verify a reset token and extract the mail
def verify_reset_token(token):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY']) # Create a serializer with the secret key
    try:
        email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=3600) # Verify the token and extract the email
    except:
        return None
    return email # Return the email if the token is valid, otherwise return None

# Function to check if the file extension is allowed or not
def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS'] # Check if the file extension is in the allowed extensions set

