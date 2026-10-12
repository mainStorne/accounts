from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.testclient import TestClient

from src.api.session import MIRROR_SESSION_KEY, MirrorAwareSessionMiddleware


def _login(request: Request) -> Response:
    request.session["uid"] = "user"
    if request.query_params.get("mirror"):
        request.session[MIRROR_SESSION_KEY] = True
    return Response()


def _logout(request: Request) -> Response:
    request.session.clear()
    return Response()


def _client() -> TestClient:
    app = Starlette(routes=[Route("/login", _login), Route("/logout", _logout)])
    app.add_middleware(MirrorAwareSessionMiddleware, secret_key="secret", same_site="lax", https_only=True)
    return TestClient(app, base_url="https://testserver")


def test_main_session_cookie_is_unchanged():
    response = _client().get("/login")
    cookie = response.headers["set-cookie"]
    assert "samesite=lax" in cookie
    assert "partitioned" not in cookie


def test_mirror_session_cookie_is_cross_site():
    response = _client().get("/login", params={"mirror": "1"})
    cookie = response.headers["set-cookie"]
    assert "samesite=none" in cookie
    assert "secure" in cookie
    assert cookie.endswith("; partitioned")


def test_cleared_mirror_session_cookie_is_deleted_as_cross_site():
    client = _client()
    client.get("/login", params={"mirror": "1"})
    response = client.get("/logout")
    cookie = response.headers["set-cookie"]
    assert cookie.startswith("session=null;")
    assert "samesite=none" in cookie
    assert cookie.endswith("; partitioned")
