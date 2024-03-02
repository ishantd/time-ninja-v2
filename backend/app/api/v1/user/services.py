from typing import Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.api.v1.auth.schemas import Provider, UserSignupPayload
from app.api.v1.user.models import (
    CreatorProfileCategories,
    Profile,
    User,
    generate_password_hash,
)


def create_user(user_signup_payload: UserSignupPayload, session: Session):
    """
    Create a user.

    Args:
        user_signup_payload (UserSignupPayload): Payload for user signup.
        session (Session, optional): Database session. Defaults to Depends(db).

    """
    email_confirmed = False if user_signup_payload.provider == Provider.EMAIL else True
    user = User(
        email=user_signup_payload.email,
        user_type=user_signup_payload.user_type,
        email_confirmed=email_confirmed,
    )
    if user_signup_payload.name:
        user.name = user_signup_payload.name
    if user_signup_payload.profile_image:
        user.profile_image = user_signup_payload.profile_image
    if user_signup_payload.password:
        user.password = generate_password_hash(user_signup_payload.password)

    session.add(user)
    session.commit()
    session.refresh(user)

    return user


def get_user_by_email_and_type(
    session: Session,
    email: str,
    user_type: str,
) -> Optional[User]:
    return session.query(User).filter_by(email=email, user_type=user_type).first()


def update_user(user: User, session: Session):
    """
    Update a user.

    Args:
        user (User): User to update.
        session (Session, optional): Database session. Defaults to Depends(db).

    """
    session.add(user)
    session.commit()
    session.refresh(user)

    return user


def create_creator_profile_categories(
    session: Session,
    name: str,
) -> CreatorProfileCategories:
    """
    Create a creator profile category.

    Args:
        session (Session, optional): Database session. Defaults to Depends(db).
        name (str): Name of the category to create.

    Returns:
        CreatorProfileCategories: Creator profile category.

    """
    if not name:
        raise HTTPException(
            status_code=400,
            detail="Name is required",
        )

    if (
        session.query(CreatorProfileCategories)
        .filter(CreatorProfileCategories.name == name)
        .first()
    ):
        raise HTTPException(
            status_code=400,
            detail="Creator profile category already exists",
        )

    creator_profile_category = CreatorProfileCategories(name=name)

    session.add(creator_profile_category)
    session.commit()
    session.refresh(creator_profile_category)

    return creator_profile_category


def attach_creator_profile_category_id_to_user_profile(
    session: Session,
    profile_id: int,
    creator_profile_category_id: int,
) -> None:
    """
    Attach a creator profile category to a user profile.

    Args:
        session (Session, optional): Database session. Defaults to Depends(db).
        profile_id (int): Profile id to attach category to.
        creator_profile_category_id (int): Category id to attach to profile.

    """
    profile = session.query(Profile).filter(Profile.id == profile_id).first()
    if not profile:
        raise HTTPException(
            status_code=400,
            detail="Profile not found",
        )

    creator_profile_category = (
        session.query(CreatorProfileCategories)
        .filter(CreatorProfileCategories.id == creator_profile_category_id)
        .first()
    )
    if not creator_profile_category:
        raise HTTPException(
            status_code=400,
            detail="Creator profile category not found",
        )

    profile.creator_profile_category_id = creator_profile_category_id
    session.add(profile)
    session.commit()
    session.refresh(profile)


def get_user_by_id(
    session: Session,
    user_id: int,
) -> Optional[User]:
    return session.query(User).filter_by(id=user_id).first()
