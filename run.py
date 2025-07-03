from inventory import create_app # Create the Flask application instance

app = create_app() # Initialize the Flask application

if __name__ == "__main__":
    app.run(debug=True) # Run the application in debug mode