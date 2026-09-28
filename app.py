@app.route("/dashboard")
def dashboard():

    # Get the database connection
    db = get_db()
    # Count failed logins
    failed_logins = db.execute(
        """
        SELECT COUNT(*)
        FROM security_events
        WHERE event_type = 'LOGIN_FAILED'
        """
    ).fetchone()[0]
