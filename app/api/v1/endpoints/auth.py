"""
Authentication endpoints.

Handles registration, login, logout, token refresh, and OAuth.
"""

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

from app.api.deps import (
    ActiveUser,
    DBSession,
    get_client_info,
)
from app.core.config import settings
from app.core.exceptions import (
    AccountDisabledException,
    AccountLockedException,
    AuthException,
    InvalidCredentialsException,
    InvalidTokenException,
    OAuthException,
    TokenRevokedException,
    UserAlreadyExistsException,
)
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
)
from app.schemas.common import ErrorResponse, MessageResponse
from app.schemas.user import UserResponse, UserWithTokens
from app.services.auth_service import AuthService
from app.services.oauth_service import GoogleOAuthService

router = APIRouter()


@router.post(
    "/register",
    response_model=UserWithTokens,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create a new user account with email and password.",
    responses={
        409: {"model": ErrorResponse, "description": "User already exists"},
        422: {"model": ErrorResponse, "description": "Validation error"},
    },
)
async def register(
    request: Request,
    register_data: RegisterRequest,
    db: DBSession,
) -> UserWithTokens:
    """
    Register a new user.

    - **email**: Valid email address
    - **password**: Strong password (min 8 chars, uppercase, lowercase, digit, special char)
    - **confirm_password**: Must match password
    - **full_name**: Optional full name
    """
    auth_service = AuthService(db)

    try:
        user, access_token, refresh_token = await auth_service.register(register_data)
    except UserAlreadyExistsException as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=e.message,
        )

    return UserWithTokens(
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            avatar_url=user.avatar_url,
            is_active=user.is_active,
            is_verified=user.is_verified,
            created_at=user.created_at,
            last_login=user.last_login,
            has_password=user.has_password,
            oauth_providers=[oa.provider for oa in user.oauth_accounts],
        ),
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/login",
    response_model=UserWithTokens,
    summary="Login",
    description="Authenticate with email and password.",
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        403: {"model": ErrorResponse, "description": "Account locked or disabled"},
    },
)
async def login(
    request: Request,
    login_data: LoginRequest,
    db: DBSession,
) -> UserWithTokens:
    """
    Login with email and password.

    Returns access and refresh tokens on success.
    """
    auth_service = AuthService(db)
    user_agent, ip_address = get_client_info(request)

    try:
        user, access_token, refresh_token = await auth_service.login(
            email=login_data.email,
            password=login_data.password,
            user_agent=user_agent,
            ip_address=ip_address,
        )
    except InvalidCredentialsException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"},
        )
    except AccountLockedException as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=e.message,
        )
    except AccountDisabledException as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=e.message,
        )

    return UserWithTokens(
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            avatar_url=user.avatar_url,
            is_active=user.is_active,
            is_verified=user.is_verified,
            created_at=user.created_at,
            last_login=user.last_login,
            has_password=user.has_password,
            oauth_providers=[oa.provider for oa in user.oauth_accounts],
        ),
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout",
    description="Logout by revoking the refresh token.",
)
async def logout(
    token_data: RefreshTokenRequest,
    db: DBSession,
) -> MessageResponse:
    """
    Logout from current session.

    Revokes the provided refresh token.
    """
    auth_service = AuthService(db)
    await auth_service.logout(token_data.refresh_token)

    return MessageResponse(message="Successfully logged out")


@router.post(
    "/logout-all",
    response_model=MessageResponse,
    summary="Logout from all devices",
    description="Revoke all refresh tokens for the current user.",
)
async def logout_all(
    current_user: ActiveUser,
    db: DBSession,
) -> MessageResponse:
    """
    Logout from all devices.

    Revokes all refresh tokens for the authenticated user.
    """
    auth_service = AuthService(db)
    count = await auth_service.logout_all(current_user)

    return MessageResponse(message=f"Logged out from {count} session(s)")


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh tokens",
    description="Get new access and refresh tokens using a valid refresh token.",
    responses={
        401: {"model": ErrorResponse, "description": "Invalid or expired token"},
    },
)
async def refresh_tokens(
    request: Request,
    token_data: RefreshTokenRequest,
    db: DBSession,
) -> TokenResponse:
    """
    Refresh access token.

    Uses refresh token rotation - the old refresh token is revoked
    and a new pair is issued.
    """
    auth_service = AuthService(db)
    user_agent, ip_address = get_client_info(request)

    try:
        access_token, refresh_token, _ = await auth_service.refresh_tokens(
            refresh_token=token_data.refresh_token,
            user_agent=user_agent,
            ip_address=ip_address,
        )
    except (InvalidTokenException, TokenRevokedException) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"},
        )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/change-password",
    response_model=MessageResponse,
    summary="Change password",
    description="Change password for authenticated user.",
    responses={
        401: {"model": ErrorResponse, "description": "Invalid current password"},
    },
)
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: ActiveUser,
    db: DBSession,
) -> MessageResponse:
    """
    Change password.

    Requires current password for verification.
    All existing sessions will be invalidated.
    """
    auth_service = AuthService(db)

    try:
        await auth_service.change_password(
            user=current_user,
            current_password=password_data.current_password,
            new_password=password_data.new_password,
        )
    except InvalidCredentialsException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
        )

    return MessageResponse(
        message="Password changed successfully. Please login again."
    )


@router.post(
    "/password-reset/request",
    response_model=MessageResponse,
    summary="Request password reset",
    description="Send password reset link to email.",
)
async def request_password_reset(
    reset_data: PasswordResetRequest,
    db: DBSession,
) -> MessageResponse:
    """
    Request password reset.

    Sends a reset link to the provided email if it exists.
    Always returns success to prevent email enumeration.
    """
    auth_service = AuthService(db)
    token = await auth_service.request_password_reset(reset_data.email)

    # In production, you would send this token via email
    # For now, we just return a generic message
    # NEVER return the token in the response in production!

    if settings.is_development and token:
        # Only in development: log the token for testing
        import logging

        logging.info(f"Password reset token for {reset_data.email}: {token}")

    return MessageResponse(
        message="If this email exists, a password reset link has been sent."
    )


@router.post(
    "/password-reset/confirm",
    response_model=MessageResponse,
    summary="Confirm password reset",
    description="Reset password using the reset token.",
    responses={
        400: {"model": ErrorResponse, "description": "Invalid or expired token"},
    },
)
async def confirm_password_reset(
    reset_data: PasswordResetConfirm,
    db: DBSession,
) -> MessageResponse:
    """
    Confirm password reset.

    Resets password using the token from email.
    All existing sessions will be invalidated.
    """
    auth_service = AuthService(db)

    try:
        await auth_service.reset_password(
            token=reset_data.token,
            new_password=reset_data.new_password,
        )
    except (InvalidTokenException, AuthException) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        )

    return MessageResponse(
        message="Password reset successfully. Please login with your new password."
    )


# =============================================================================
# Google OAuth Endpoints
# =============================================================================


@router.get(
    "/google",
    summary="Google OAuth login",
    description="Redirect to Google for authentication.",
    responses={
        307: {"description": "Redirect to Google"},
        501: {"model": ErrorResponse, "description": "OAuth not configured"},
    },
)
async def google_login(
    request: Request,
    redirect_to: Annotated[str | None, Query(description="URL to redirect to after login")] = None,
) -> RedirectResponse:
    """
    Initiate Google OAuth flow.

    Redirects to Google's authorization page.
    """
    if not settings.google_oauth_enabled:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Google OAuth is not configured",
        )

    # Validate redirect_to to prevent open redirect vulnerabilities
    # In a real app, you should check if the domain is allowed
    # For now, we allow any URL as requested, but you might want to restrict this later
    
    # Store state including redirect_to
    # We use a JSON object encoded in the state parameter
    import json
    import base64
    
    state_data = {
        "token": secrets.token_urlsafe(32),
        "redirect_to": redirect_to
    }
    # Encode state as base64 url safe string to pass to Google
    state_json = json.dumps(state_data)
    state = base64.urlsafe_b64encode(state_json.encode()).decode()

    # Dynamic redirect URI based on current request
    redirect_uri = str(request.url_for("google_callback"))
    
    if settings.is_production and redirect_uri.startswith("http:"):
        redirect_uri = "https" + redirect_uri[4:]

    oauth_service = GoogleOAuthService(db=None)  # type: ignore
    auth_url = oauth_service.get_authorization_url(redirect_uri=redirect_uri, state=state)

    return RedirectResponse(url=auth_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get(
    "/google/callback",
    summary="Google OAuth callback",
    description="Handle Google OAuth callback and authenticate user.",
    responses={
        400: {"model": ErrorResponse, "description": "OAuth error"},
    },
)
async def google_callback(
    request: Request,
    code: Annotated[str, Query(description="Authorization code from Google")],
    state: Annotated[str | None, Query(description="State parameter")] = None,
    db: DBSession = None,  # type: ignore
) -> RedirectResponse:
    """
    Handle Google OAuth callback.

    Exchanges authorization code for tokens and redirects to frontend
    with tokens in URL fragment (hash) for security.
    """
    if not settings.google_oauth_enabled:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Google OAuth is not configured",
        )
    
    # Decode state to get redirect_to
    redirect_to = None
    if state:
        try:
            import json
            import base64
            # Try to decode as JSON state
            decoded = base64.urlsafe_b64decode(state).decode()
            state_data = json.loads(decoded)
            if isinstance(state_data, dict):
                redirect_to = state_data.get("redirect_to")
        except Exception:
            # If failed to decode (e.g. old style state), ignore
            pass

    # Default redirect if None provided
    if not redirect_to:
        redirect_to = "/test"

    oauth_service = GoogleOAuthService(db)
    user_agent, ip_address = get_client_info(request)

    # Dynamic redirect URI based on current request
    redirect_uri = str(request.url_for("google_callback"))
    
    if settings.is_production and redirect_uri.startswith("http:"):
        redirect_uri = "https" + redirect_uri[4:]

    try:
        user, access_token, refresh_token, is_new_user = await oauth_service.authenticate(
            code=code,
            redirect_uri=redirect_uri,
            user_agent=user_agent,
            ip_address=ip_address,
        )
    except OAuthException as e:
        # Redirect to frontend with error
        separator = "&" if "?" in redirect_to else "?"
        error_url = f"{redirect_to}{separator}error={e.message}"
        return RedirectResponse(url=error_url, status_code=status.HTTP_302_FOUND)

    # Build redirect URL with tokens in fragment
    import json
    from urllib.parse import quote
    
    user_data = {
        "id": str(user.id),
        "email": user.email,
        "full_name": user.full_name,
        "avatar_url": user.avatar_url,
        "is_active": user.is_active,
        "is_verified": user.is_verified,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }
    
    user_json = quote(json.dumps(user_data))
    
    # Append fragment to redirect_to
    # Note: Fragments are not sent to server, so this is safe for tokens
    redirect_url = (
        f"{redirect_to}"
        f"#access_token={access_token}"
        f"&refresh_token={refresh_token}"
        f"&user={user_json}"
        f"&is_new_user={str(is_new_user).lower()}"
    )
    
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)


@router.delete(
    "/google/unlink",
    response_model=MessageResponse,
    summary="Unlink Google account",
    description="Remove Google OAuth link from account.",
    responses={
        400: {"model": ErrorResponse, "description": "Cannot unlink"},
    },
)
async def unlink_google(
    current_user: ActiveUser,
    db: DBSession,
) -> MessageResponse:
    """
    Unlink Google account.

    Requires user to have another login method (password).
    """
    oauth_service = GoogleOAuthService(db)

    try:
        unlinked = await oauth_service.unlink_account(current_user)
    except OAuthException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        )

    if not unlinked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No Google account linked",
        )

    return MessageResponse(message="Google account unlinked successfully")
