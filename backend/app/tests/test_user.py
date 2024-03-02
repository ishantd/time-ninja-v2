import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.api.v1.user import services


def test_create_creator_profile_categories(
    dbsession: Session,
):
    creator_profile_category = services.create_creator_profile_categories(
        session=dbsession,
        name="Test Creator Profile Category",
    )

    assert creator_profile_category.id is not None
    assert creator_profile_category.name == "Test Creator Profile Category"


def test_create_duplicate_creator_profile_categories(
    dbsession: Session,
):
    services.create_creator_profile_categories(
        session=dbsession,
        name="Test Creator Profile Category 2",
    )

    with pytest.raises(HTTPException) as exc:
        services.create_creator_profile_categories(
            session=dbsession,
            name="Test Creator Profile Category 2",
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == "Creator profile category already exists"
