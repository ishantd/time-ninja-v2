import bcrypt
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from starlette import status

from app.api.v1.auth import schemas
from app.api.v1.auth import services as auth_services
from app.api.v1.user.models import User


def test_valid_password():
    passwords_to_test = [
        ("12345", False),  # not long enough
        ("12345678", False),  # no letters
        ("AAAAAAAAA", False),  # no numeric characters
        ("123aaaAAA", False),  # no special characters
        ("123aaaAAA$$$", True),
    ]

    for password, expected_validity in passwords_to_test:
        validity = auth_services.is_valid_password(password)
        assert validity == expected_validity


def test_check_password_hash():
    from app.api.v1.auth.services import check_password_hash

    hashed_password = bcrypt.hashpw(
        "Password@123".encode("ascii"),
        bcrypt.gensalt(),
    ).decode("ascii")
    assert check_password_hash("Password@123", hashed_password) == True  # noqa
    assert check_password_hash("WrongPassword", hashed_password) == False  # noqa


# 1. Test User Registration
def test_signup_new_user(client: TestClient):
    data = {
        "provider": "email",
        "user_type": "creator",
        "email": "newuser@test.com",
        "name": "New User",
        "password": "StrongPassword@123",
    }

    response = client.post("/v1/auth/signup/", json=data)
    assert response.status_code == 201


def test_register_existing_user(client: TestClient, dbsession: Session):
    existing_email = "test5@test.com"

    # Assuming you have a function to get a user by email in your services.
    user = User.get_by_email_and_type(
        dbsession,
        existing_email,
        schemas.UserType.CREATOR,
    )

    if user:
        data = {
            "provider": "EMAIL",
            "user_type": "creator",
            "email": existing_email,
            "password": "StrongPassword@123",
        }

        response = client.post("/v1/auth/signup/", json=data)

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "already registered" in response.json()["detail"]


# 2. Test User Login
def test_valid_login(client: TestClient):
    data = {
        "provider": "email",
        "user_type": "creator",
        "email": "newuser@test.com",
        "password": "StrongPassword@123",
    }

    response = client.post("/v1/auth/login/", json=data)

    assert response.status_code == 200
    assert "X-Access-Token" in response.headers


def test_invalid_login(client: TestClient):
    data = {
        "provider": "email",
        "user_type": "creator",
        "email": "newuser@test.com",
        "password": "strongpassword1s23",
    }

    response = client.post("/v1/auth/login/", json=data)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "Invalid" in response.json()["detail"]


def test_whoami(auth_creator_client: TestClient):
    response = auth_creator_client.get("/v1/auth/whoami/")
    assert response.status_code == 200
    assert response.json()["email"] == "auth_creator_client@test.com"


def test_whoami_businness(auth_business_client: TestClient):
    response = auth_business_client.get("/v1/auth/whoami/")
    assert response.status_code == 200
    assert response.json()["email"] == "auth_business_client@test.com"
