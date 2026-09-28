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
    
    # Count SQL injection detections
    sql_detections = db.execute(
        """
        SELECT COUNT(*)
        FROM security_events
        WHERE event_type = 'SQLI_ATTEMPT'
        """
    ).fetchone()[0]

    # Count brute force detections
    brute_force_detections = db.execute(
        """
        SELECT COUNT(*)
        FROM security_events
        WHERE event_type = 'BRUTE_FORCE_DETECTED'
        """
    ).fetchone()[0]

    # Get the newest security events
    events = db.execute(
        """
        SELECT timestamp, event_type, source_ip, details, detected
        FROM security_events
        ORDER BY timestamp DESC
        LIMIT 20
        """
    ).fetchall()
