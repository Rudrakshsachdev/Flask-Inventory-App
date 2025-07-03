# from inventory import create_app
# from inventory.extensions import db
# from inventory.models import Product, Order, User

# app = create_app()  # Create the Flask application instance

# with app.app_context():
#     db.drop_all()
#     db.create_all()
#     print("Database tables created successfully.")

from inventory import create_app, db
from inventory.models import User

app = create_app()
with app.app_context():
    user = User.query.filter_by(email='your_admin_email@example.com').first()
    if user:
        user.role = 'admin'
        user.is_admin_verified = True  # assuming you are using this for verification
        db.session.commit()
