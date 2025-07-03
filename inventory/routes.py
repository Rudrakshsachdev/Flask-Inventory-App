from flask import blueprints, render_template, request, redirect, url_for, flash, current_app
from .models import Product, Order, allowed_file, User
from .extensions import db
from flask_login import login_required
from werkzeug.utils import secure_filename # Importing secure_filename to safely handle file names
import os
from .auth_routes import admin_required


main = blueprints.Blueprint('main', __name__) # Defining the main blueprint

# Route for the home page
@main.route('/') 
@login_required
def dashboard():
    products = Product.query.all() # Fetching all the products from the database
    return render_template('dashboard.html', products=products)

# Route to add a new product
@main.route('/add_product', methods=['GET', 'POST'])
@login_required # Ensuring that only logged-in users can access this route
@admin_required # Ensuring that only admin users can access this route
def add_product():
    # Getting out all the form data when the form is submitted
    if request.method == 'POST':
        name = request.form['name'] 
        description = request.form['description']
        price = float(request.form['price'])


        
        quantity = int(request.form['quantity'])
        image_file = request.files.get('image') # Getting the uploaded image file
        image_filename = None # Initializing the image filename variable


        # This block handles the image upload and saving
        
        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path) # Saving the uploaded image file to the specified path
            print(f"Image saved at: {image_path}")
            image_filename = filename # Setting the image filename to the saved file name


        # Creating a new product instance with the form data
        new_product = Product(name=name, description=description, price=price, quantity=quantity, image=image_filename)

        db.session.add(new_product) # Adding the new product to the database session
        db.session.commit() # saving the changes to the database

        flash('Product added successfully!', 'success') # Flashing a success message
        
        return redirect(url_for('main.dashboard')) # redirecting to the dashboard
    
    return render_template('add_product.html') # Rendering the add product form


# route to edit an existing product
@main.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required # Ensuring that only admin users can access this route

def edit_product(id):
    product = Product.query.get_or_404(id)

    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        product.quantity = int(request.form['quantity'])

        image_file = request.files.get('image')
        old_image = product.image

        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)

            # Delete old image if not the same
            if old_image and old_image != filename:
                old_path = os.path.join(current_app.config['UPLOAD_FOLDER'], old_image)
                if os.path.exists(old_path):
                    os.remove(old_path)

            product.image = filename

        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('main.dashboard'))

    return render_template('edit_product.html', product=product)



# Route for Placing an order
@main.route('/order/', methods=['GET', 'POST'])
@login_required
def create_order():
    product = Product.query.all()

    if request.method == 'POST':
        product_id = int(request.form['product_id'])
        customer_name = request.form['customer_name']
        quantity = int(request.form['quantity'])

        product = Product.query.get_or_404(product_id) # Fetching the product by its ID or returning a 404 error if not found

        # Checking if the product is available in sufficient quantity
        if product and product.quantity >= quantity:
            product.quantity -= quantity # reducing the product quantity in the inventory

            order = Order(product_id=product_id, customer_name=customer_name, quantity=quantity) # Creating a new order instance with the form data
            db.session.add(order) # Adding the new order to the database session
            db.session.commit() # Saviing the change to the database
            flash('Order placed successfully!', 'success') # Flashing a success message
        else:
            flash('Insufficient product quantity available!', 'danger') # Flashing an error message if the product is not available in the inventory
        
        return redirect(url_for('main.view_orders')) # redirecting to the view orders page
    
    return render_template('create_order.html', product=product) 

# Route to view all orders
@main.route('/orders')
@login_required
def view_orders():
    orders = Order.query.all()
    return render_template('view_orders.html', orders=orders)

# Route to delete a product
@main.route('/delete/<int:id>')
@login_required
@admin_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('main.dashboard'))


# Route to view admin orders
@main.route('/admin/orders')
@login_required 
@admin_required
# function to view all orders for the admin 
def admin_orders():
    orders = Order.query.order_by(Order.order_date.desc()).all() # fetching out all the orders from the database in descending order of the order date
    return render_template('admin_orders.html', orders = orders)

# route for admin dashboard
@main.route('/admin/')
@login_required
@admin_required
def admin_dashboard():
    products = Product.query.all()
    orders = Order.query.all()
    return render_template('admin_dashboard.html', products = products, orders = orders)



