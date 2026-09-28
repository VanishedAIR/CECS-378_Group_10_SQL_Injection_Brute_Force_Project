@app.route("/dashboard")
def dashboard():

    # Get the database connection
    db = get_db()

