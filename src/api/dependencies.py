__all__ = ["UserIdDep", "OptionalUserIdDep", "UserDep", "AdminDep", "is_impersonating"]

import time
from typing import Annotated

from beanie import PydanticObjectId
from fastapi import Depends, Request
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwt import JWTClaimsRegistry

from src.exceptions import NotEnoughPermissionsException, UserWithoutSessionException
from src.modules.tokens.repository import TokenRepository
from src.modules.users.repository import user_repository
from src.storages.mongo.models import User

IMPERSONATE_MAX_AGE_SEC = 4 * 60 * 60  # 4 hours


async def _get_uid_from_session(request: Request) -> PydanticObjectId:
    uid = await _get_optional_uid_from_session(request)
    if uid is None:
        raise UserWithoutSessionException()
    return uid


def is_impersonating(request: Request) -> bool:
    impersonate_until = request.session.get("impersonate_until")
    return bool(request.session.get("impersonate_uid") and impersonate_until and time.time() < impersonate_until)


def _get_uid_from_my_token(request: Request) -> str | None:
    """
    Get uid from 'my token' (scope `me`) in the Authorization header. It lets the frontend use the API without
    the session cookie, e.g. through a mirror host on another domain, where the browser doesn't send the cookie.
    Impersonation tokens are skipped, so they can't be renewed via /tokens/generate-my-token past the impersonation.
    """
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    try:
        claims = jwt.decode(token, TokenRepository.public_jwt_key).claims
        JWTClaimsRegistry().validate(claims)
    except JoseError:
        return None
    scope_string = claims.get("scope", None)
    scopes = scope_string.split() if scope_string else []
    if "me" not in scopes or claims.get("aud") or claims.get("impersonated"):
        return None
    return claims.get("uid")


async def _get_optional_uid_from_session(request: Request) -> PydanticObjectId | None:
    if is_impersonating(request):
        impersonate_uid = request.session.get("impersonate_uid")
        try:
            uid = PydanticObjectId(impersonate_uid)
            if await user_repository.exists(uid):
                return uid
        except Exception:
            pass
        request.session.pop("impersonate_uid", None)
        request.session.pop("impersonate_until", None)

    uid = request.session.get("uid") or _get_uid_from_my_token(request)
    if uid is None:
        return None
    uid = PydanticObjectId(uid)
    exists = await user_repository.exists(uid)
    if not exists:
        request.session.clear()
        raise UserWithoutSessionException()

    return uid


async def _get_user(request: Request) -> User:
    user_id = await _get_uid_from_session(request)
    user = await user_repository.read(user_id)
    if user is None:
        raise UserWithoutSessionException()
    return user


async def _get_admin_dep(user: User = Depends(_get_user)) -> User:
    if not user.is_admin:
        raise NotEnoughPermissionsException("You are not an admin")
    return user


async def get_optional_admin_from_session(request: Request) -> User | None:
    uid = await _get_optional_uid_from_session(request)
    if uid is None:
        return None
    user = await user_repository.read(uid)
    if user is None or not user.is_admin:
        return None
    return user


UserIdDep = Annotated[PydanticObjectId, Depends(_get_uid_from_session)]
OptionalUserIdDep = Annotated[PydanticObjectId | None, Depends(_get_optional_uid_from_session, use_cache=False)]
UserDep = Annotated[User, Depends(_get_user)]
AdminDep = Annotated[User, Depends(_get_admin_dep)]
