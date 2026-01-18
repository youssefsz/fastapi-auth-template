"""
User management endpoints.

Provides protected endpoints for user profile management.
"""

from fastapi import APIRouter, HTTPException, status

from app.api.deps import ActiveUser, DBSession, VerifiedUser
from app.schemas.common import MessageResponse
from app.schemas.user import UserResponse, UserUpdate
from app.services.user_service import UserService

router = APIRouter()


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user",
    description="Get the profile of the currently authenticated user.",
)
async def get_current_user_profile(
    current_user: ActiveUser,
) -> UserResponse:
    """
    Get current user profile.

    Returns the authenticated user's profile data.
    """
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        avatar_url=current_user.avatar_url,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
        has_password=current_user.has_password,
        oauth_providers=[oa.provider for oa in current_user.oauth_accounts],
    )


@router.patch(
    "/me",
    response_model=UserResponse,
    summary="Update current user",
    description="Update the profile of the currently authenticated user.",
)
async def update_current_user_profile(
    update_data: UserUpdate,
    current_user: ActiveUser,
    db: DBSession,
) -> UserResponse:
    """
    Update current user profile.

    Allows updating full_name and avatar_url.
    """
    user_service = UserService(db)
    updated_user = await user_service.update(current_user, update_data)

    return UserResponse(
        id=updated_user.id,
        email=updated_user.email,
        full_name=updated_user.full_name,
        avatar_url=updated_user.avatar_url,
        is_active=updated_user.is_active,
        is_verified=updated_user.is_verified,
        created_at=updated_user.created_at,
        last_login=updated_user.last_login,
        has_password=updated_user.has_password,
        oauth_providers=[oa.provider for oa in updated_user.oauth_accounts],
    )


@router.delete(
    "/me",
    response_model=MessageResponse,
    summary="Delete current user",
    description="Delete the currently authenticated user's account.",
)
async def delete_current_user(
    current_user: VerifiedUser,
    db: DBSession,
) -> MessageResponse:
    """
    Delete current user account.

    This action is irreversible. Requires verified email.
    """
    user_service = UserService(db)
    await user_service.delete(current_user)

    return MessageResponse(message="Account deleted successfully")


# =============================================================================
# Example Protected Endpoints
# =============================================================================


@router.get(
    "/protected-example",
    response_model=MessageResponse,
    summary="Protected endpoint example",
    description="Example of a protected endpoint that requires authentication.",
)
async def protected_example(
    current_user: ActiveUser,
) -> MessageResponse:
    """
    Protected endpoint example.

    Requires valid JWT access token.
    """
    return MessageResponse(
        message=f"Hello, {current_user.full_name or current_user.email}! "
        f"This is a protected endpoint."
    )


@router.get(
    "/verified-only-example",
    response_model=MessageResponse,
    summary="Verified users only example",
    description="Example endpoint that requires email verification.",
)
async def verified_only_example(
    current_user: VerifiedUser,
) -> MessageResponse:
    """
    Verified users only endpoint.

    Requires valid JWT and verified email.
    """
    return MessageResponse(
        message=f"Hello, {current_user.full_name or current_user.email}! "
        f"Your email is verified."
    )
