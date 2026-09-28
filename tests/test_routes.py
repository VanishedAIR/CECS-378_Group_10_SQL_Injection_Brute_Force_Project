def test_dashboard_opens(client):

    # Open the dashboard
    response = client.get("/dashboard")

    # 200 means the page opened correctly
    assert response.status_code == 200

def test_dashboard_shows_events(client, db):

    # Add fake security events for the test
    db.execute(
        """
        INSERT INTO security_events
        (timestamp, event_type, source_ip, details, detected)
        VALUES (?, ?, ?, ?, ?)
        """,
