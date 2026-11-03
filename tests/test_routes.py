from app import create_app


def test_login_page_renders():
    app = create_app({"TESTING": True})
    client = app.test_client()

    response = client.get('/login')

    assert response.status_code == 200
    assert b'Login' in response.data
