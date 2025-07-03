from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash # Import password hashing functions
from flask_login import login_user, logout_user, login_required, current_user # Import login manager functions
from .models import User, generate_reset_token, verify_reset_token, allowed_file
from .extensions import db, mail
from flask_mail import Message # Import the Message class from Flask-Mail for sending emails
import os # for file path operatiions
from werkzeug.utils import secure_filename # Import secure_filename to secure the file names
from flask import current_app, session

from flask import abort # Import abort to handle errors
from functools import wraps # Import wraps to create decorators
import random # Import random for generating random numbers


auth = Blueprint('auth', __name__) # creating a blueprint for authentication routes

"""The admin_required decorator restricts access to a function so that only users with the 'admin' role can access it. If a non-admin user tries to access the decorated route/function, it returns a 403 Forbidden error."""

def admin_required(f):
    @wraps(f) # This decorator is used to restrict access to admin users only
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            abort(403) # if the current use ris not an admin, abort with a 403 forbidden error
            return f(*args, **kwargs) # if the user is an admin, proceed with the funnction
    return decorated_function 

@auth.route('/')
def index():
    return redirect(url_for('auth.login'))





"""The register function handles user registration. It processes form data submitted via POST, optionally saves a profile image, checks if the email already exists, and if not, hashes the password, creates a new user with the role 'user', stores the user in the database, and redirects them to the login page with a success message."""

@auth.route('/register', methods=['GET', 'POST']) 

def register():
    # fetch the form data when the form is submitted
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        profile_image = request.files.get('profile_image')
        profile_filename = None # this will hold the profile image filename if uploaded

        # Check if a profile image is uploaded and if the file type is allowed then save it
        if profile_image and allowed_file(profile_image.filename):
            filename = secure_filename(profile_image.filename)
            profile_path = os.path.join(current_app.config['PROFILE_IMG_FOLDER'], filename) # constructing the file path for the profile image
            profile_image.save(profile_path)
            print(f"Profile image saved at: {profile_path}")
            profile_filename = filename




        existing_user = User.query.filter_by(email=email).first() # Checking if the user already exists with the same email
        if existing_user:
            flash('Email already exists! Please log in.', 'warning')
            return redirect(url_for('auth.register')) # Redirecting to login page if the user already exists


        hashed_password = generate_password_hash(password) # Hashing the password for security

        user = User(name=name, email=email, password=hashed_password, profile_image = profile_filename, role = 'user') # Creating a new user instance with the form data
        db.session.add(user)
        db.session.commit()

        flash('Account Created Successfully! Please log in.', 'success') # Flashing a success message
        return redirect(url_for('auth.login'))

    return render_template('register.html')



"""The login function handles user authentication. It checks the submitted email and password against the database. If valid, it logs in the user and redirects them to the dashboard; otherwise, it shows an error message. The login page is rendered for GET requests."""

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first() # Filtering out the user by email

        # check if the user exists and if the password matches
        if user and check_password_hash(user.password, password):
            login_user(user) # logging in the user
            flash('Login Successful!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login Unsuccessful! Please check your email and password.', 'danger') # Flashing an error message if login fails 
    
    return render_template('login.html')



# Route for user logout
@auth.route('/logout')
def logout():
    logout_user()
    flash('Logged out successfully!', 'success') # flashing a success message
    return redirect(url_for('auth.login')) # redirecting to login page after logout



# Route to view the user profile
@auth.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)



"""The edit_profile function allows logged-in users to update their profile information (name, email, and profile image). It processes form data, handles optional profile image upload securely, updates the database, and flashes a success message upon completion."""

@auth.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    # Fetching the current user's profile data to pre-fill the form
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.email = request.form['email']
        image_file = request.files.get('profile_image')

        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename) # Securing the filename to prevent directory traversal attacks
            img_path = os.path.join(current_app.config['PROFILE_IMG_FOLDER'], filename)
            image_file.save(img_path)
            print(f"Image saved at: {img_path}")
            current_user.profile_image = filename 

        db.session.commit()

        flash('Profile updated successfully!', 'success') 
        return redirect(url_for('auth.profile'))
    return render_template('edit_profile.html', user=current_user)




"""The change_password function allows logged-in users to update their password. It verifies the old password, ensures the new and confirm passwords match, updates the password securely using hashing, and commits the change to the database with appropriate success or error messages."""

@auth.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # STEP 1: check if the old password matches with the current one or not
        if not check_password_hash(current_user.password, current_password):
            flash('Old password is incorrect!', 'danger') # Flashing an error message if the old password is incorrect
            return redirect(url_for('auth.change_password'))
        
        # STEP 2: check if the new password and confirm password matches
        if new_password != confirm_password:
            flash('New Password and Confirm Password do not match!', 'danger')
            return redirect(url_for('auth.change_password'))
        
        # STEP 3: Update the password
        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('auth.profile'))
    return render_template('change_password.html', user=current_user) 



"""The forgot_password function handles password reset requests. When a user submits their email, it checks if the user exists, generates a secure reset token, creates a reset link, and sends it via email. If the email isn't found, it flashes an error message. The reset page is shown for GET requests."""


@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email = email).first() # fetching the use by the email
        if user:
            token = generate_reset_token(email)
            reset_url = url_for('auth.reset_password', token = token, _external = True) # generating the reset password URL with the token
            msg = Message('Password Reset Request', sender='rudrakshsachdeva22@gmail.com', recipients=[email]) # creating a message instance for the email
            msg.body = f"Hi {user.name}, \n\nTo reset your password, click the following Link: {reset_url}\n\nIf you did not make this request, please ignore this email."
            mail.send(msg) # sending the email with the reset password link
            flash('A password reset link has been sent to your email.', 'info') # Flashing an info message
        else:
            flash('No account found with that email address.', 'danger')
            return redirect(url_for('auth.forgot_password')) # Redirecting to the forgot password page if no account found with that email
        
    return render_template('forgot_password.html')



"""The reset_password function allows users to set a new password using a valid reset token. It verifies the token, fetches the user, checks if the new and confirm passwords match, hashes the new password, updates it in the database, and then redirects the user to the login page with a success message."""

@auth.route('/reset_password/<token>', methods = ['GET', 'POST'])
def reset_password(token):
    email = verify_reset_token(token)

    # If the token is valid, it will return the email, otherwise it will return None
    if not email:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('auth.forgot_password'))
    
    user = User.query.filter_by(email=email).first() # fetching out the user by the email

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # STEP 1: check if the new password and confirm password matches
        if new_password != confirm_password:
            flash('New Password and Confirm Password do not match!', 'danger')
            return redirect(url_for('auth.reset_password', token=token)) 
        
        # STEP 2: Update the password
        user.password = generate_password_hash(new_password) # Hashing the new password
        db.session.commit()
        flash('Your password has been reset successfully!', 'success')
        return redirect(url_for('auth.login')) 
    
    return render_template('reset_password.html', token=token)


# function to generate a random otp
def generate_otp():
    return str(random.randint(100000, 999999)) # Generating a random 6-digit OTP

def send_admin_otp(email, otp):
    msg = Message('Your Admin OTP verification Code',
                sender = 'YOUR-EMAIL-ID',
                recipients = [email])
    msg.body = f"Your OTP for admin verification is: {otp}\n\nPlease use this OTP to verify your admin account."
    mail.send(msg)



admin_otp_store = {} # this dictionary will hold the OTPs for admin verification


"""The admin_register function handles admin registration by collecting the form data (name, email, password), temporarily storing it in the session, generating an OTP, sending it to the admin’s email, and then redirecting to the OTP verification page."""

@auth.route('/admin/register', methods = ['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # storing the admin registration data in the session for temporary storage
        session['admin_reg_data'] = {'email': email, 'name': name, 'password': password}

        otp = generate_otp()
        admin_otp_store[email] = otp # Storing the OTP in the dictionary
        send_admin_otp(email, otp) # Sending the OTP to the admins email

        flash('An OTP has been sent to your email for verification.', 'info')
        return redirect(url_for('auth.admin_verify'))
    return render_template('admin_register.html')


"""The admin_verify function completes the admin registration process by validating the OTP entered by the user. If the OTP matches the one stored for the email, it creates a new admin account, commits it to the database, clears session and OTP data, and redirects to the admin login page. If not, it displays an error message."""

@auth.route('/admin/verify', methods = ['GET', 'POST'])
def admin_verify():
    if request.method == 'POST':
        otp_input = request.form['otp']
        data = session.get('admin_reg_data', None)


        # check if the otp is valid and matches the one sent to the email
        if not data:
            flash('Session expired. Please register again.', 'danger')
            return redirect(url_for('auth.admin_register'))
        
        stored_otp = admin_otp_store.get(data['email'], None) # Fetching the stored OTP for the email from the dictionary
        if otp_input == stored_otp:
            new_admin = User(
                name = data['name'],
                email = data['email'],
                password = data['password'],
                role = 'admin',
                is_admin_verified = True,
            )

            db.session.add(new_admin)
            db.session.commit()

            admin_otp_store.pop(data['email'], None) 
            session.pop('admin_reg_data', None) # clearing the session data after successful registration

            flash('Admin account created successfully!', 'success')
            return redirect(url_for('auth.admin_login'))
        else:
            flash('Invalid OTP! Please try again.', 'danger')
    
    return render_template('admin_verify.html')




"""The admin_login function handles admin authentication. It verifies the admin's email and password, checks if the admin account is verified, and if valid, logs in the user and redirects to the admin dashboard. If authentication fails, it shows an appropriate error message."""

@auth.route('/admin/login', methods = ['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email = email, role = 'admin').first() # fetching the admin user by email

        # check if the user exists and if the password matches
        if user and check_password_hash(user.password, password):
            if not user.is_admin_verified:
                flash('Your admin account is not verified yet. Please contact support.', 'warning')
                return redirect(url_for('auth.admin_login'))
            
            login_user(user) # logging in the admin user
            flash('Admin login successful!', 'success')
            return redirect(url_for('main.admin_dashboard'))
        else:
            flash('Login Unsuccessful! Please check your email and password.', 'danger')

    return render_template('admin_login.html')

