def test_dashboard_opens(client):

    # Open the dashboard
    response = client.get("/dashboard")

    # 200 means the page opened correctly
    assert response.status_code == 200
