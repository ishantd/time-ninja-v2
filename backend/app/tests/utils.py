import random

from faker import Faker
from sqlalchemy.orm import Session

from app.api.v1.auth.schemas import UserSignupPayload
from app.api.v1.auth.services import create_user
from app.api.v1.instagram.models import InstagramProfile, InstagramProfileCategories
from app.api.v1.user.models import CreatorProfileCategories, User
from app.api.v1.workspace.models import Workspace
from app.utils.strings import generate_random_string

fake = Faker()


def random_email() -> str:
    """Generate a random email."""
    return generate_random_string(10) + "@test.com"


def random_instagram_pk() -> int:
    """Generate a random instagram pk."""
    return random.randint(1000000000, 9999999999)


def random_username() -> str:
    """Generate a random username."""
    username = fake.user_name()
    if len(username) > 30:
        return username[:30]
    return username


def create_basic_user(
    dbsession: Session,
    email: str = None,
    password: str = "password",
    user_type: str = "creator",
) -> User:
    """Utility function to create a basic user."""
    if not email:
        email = generate_random_string(10) + "@test.com"
    signup_payload = UserSignupPayload(
        provider="email",
        user_type=user_type,
        email=email,
        password=password,
    )
    user = create_user(
        user_signup_payload=signup_payload,
        session=dbsession,
    )
    return user


def create_basic_workspace(
    dbsession: Session,
    name: str = None,
    description: str = "Description for basic workspace",
    owner_id: int = 1,
) -> Workspace:
    """Utility function to create a basic workspace."""
    if not name:
        name = generate_random_string(10)
    workspace = Workspace(
        name=name,
        description=description,
        shortcode=generate_random_string(8),
    )
    dbsession.add(workspace)
    dbsession.commit()

    workspace.attach_owner(
        session=dbsession,
        user_id=owner_id,
    )
    return workspace


def create_basic_creator_profile_category(
    dbsession: Session,
    name: str = "Basic creator custom category 2",
    description: str = "Basic creator custom category description 2",
) -> CreatorProfileCategories:
    """Utility function to create a basic creator profile category."""

    name = name + generate_random_string(5)

    creator_profile_category = CreatorProfileCategories(
        name=name,
        description=description,
    )
    dbsession.add(creator_profile_category)
    dbsession.commit()
    return creator_profile_category


def create_basic_instagram_profile_category(
    dbsession: Session,
    name: str = "Basic ig custom category",
    description: str = "Basic ig custom category description",
    creator_profile_category_id: int = 1,
) -> InstagramProfileCategories:
    """Utility function to create a basic instagram profile category."""

    name = name + generate_random_string(5)

    instagram_profile_category = InstagramProfileCategories(
        name=name,
        description=description,
        creator_profile_category_id=creator_profile_category_id,
    )
    dbsession.add(instagram_profile_category)
    dbsession.commit()
    return instagram_profile_category


def create_basic_instagram_profile(
    dbsession: Session,
    ig_pk: int = 0,
    username: str = None,
    follower_count: int = 100,
    following_count: int = 100,
    media_count: int = 100,
    biography: str = "Basic biography",
    category: str = "Basic category",
    full_name: str = fake.name(),
    is_private: bool = False,
    city_name: str = fake.city(),
) -> InstagramProfile:
    """Utility function to create a basic instagram profile."""
    if not username:
        username = fake.user_name()
    if ig_pk == 0:
        ig_pk = random_instagram_pk()

    basic_creator_profile_category = create_basic_creator_profile_category(
        dbsession=dbsession,
    )

    basic_instagram_profile_category = create_basic_instagram_profile_category(
        dbsession=dbsession,
        creator_profile_category_id=basic_creator_profile_category.id,
    )

    instagram_profile = InstagramProfile(
        ig_pk=ig_pk,
        username=username,
        follower_count=follower_count,
        following_count=following_count,
        media_count=media_count,
        biography=biography,
        category=category,
        full_name=full_name,
        is_private=is_private,
        city_name=city_name,
        instagram_profile_category_id=basic_instagram_profile_category.id,
    )
    dbsession.add(instagram_profile)
    dbsession.commit()
    return instagram_profile
