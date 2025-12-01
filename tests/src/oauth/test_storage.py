"""Tests for OAuth storage."""

import time
from pydantic import AnyUrl

from mcp.server.auth.provider import AuthorizationCode, AccessToken
from mcp.shared.auth import OAuthClientInformationFull

from assisted_service_mcp.src.oauth.storage import OAuthStorage


class TestOAuthStorage:
    """Test cases for OAuthStorage."""

    def test_store_and_get_authorization_code(self) -> None:
        """Test storing and retrieving an authorization code."""
        storage = OAuthStorage()

        auth_code = AuthorizationCode(
            code="test_code_123",
            scopes=["openid", "profile"],
            expires_at=time.time() + 600,
            client_id="test_client",
            code_challenge="test_challenge",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
        )

        storage.store_authorization_code(auth_code)
        retrieved = storage.get_authorization_code("test_code_123")

        assert retrieved is not None
        assert retrieved.code == "test_code_123"
        assert retrieved.client_id == "test_client"
        assert retrieved.scopes == ["openid", "profile"]

    def test_get_authorization_code_single_use(self) -> None:
        """Test that authorization codes are single-use."""
        storage = OAuthStorage()

        auth_code = AuthorizationCode(
            code="test_code_456",
            scopes=["openid"],
            expires_at=time.time() + 600,
            client_id="test_client",
            code_challenge="test_challenge",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
        )

        storage.store_authorization_code(auth_code)

        # First retrieval should succeed
        retrieved = storage.get_authorization_code("test_code_456")
        assert retrieved is not None

        # Second retrieval should return None (single-use)
        retrieved_again = storage.get_authorization_code("test_code_456")
        assert retrieved_again is None

    def test_get_expired_authorization_code(self) -> None:
        """Test that expired authorization codes are not returned."""
        storage = OAuthStorage()

        auth_code = AuthorizationCode(
            code="expired_code",
            scopes=["openid"],
            expires_at=time.time() - 1,  # Already expired
            client_id="test_client",
            code_challenge="test_challenge",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
        )

        storage.store_authorization_code(auth_code)
        retrieved = storage.get_authorization_code("expired_code")

        assert retrieved is None

    def test_store_and_get_access_token(self) -> None:
        """Test storing and retrieving an access token."""
        storage = OAuthStorage()

        access_token = AccessToken(
            token="test_access_token",
            client_id="test_client",
            scopes=["openid", "profile"],
            expires_at=int(time.time() + 3600),
        )

        storage.store_access_token(access_token)
        retrieved = storage.get_access_token("test_access_token")

        assert retrieved is not None
        assert retrieved.token == "test_access_token"
        assert retrieved.client_id == "test_client"
        assert retrieved.scopes == ["openid", "profile"]

    def test_get_expired_access_token(self) -> None:
        """Test that expired access tokens are not returned."""
        storage = OAuthStorage()

        access_token = AccessToken(
            token="expired_token",
            client_id="test_client",
            scopes=["openid"],
            expires_at=int(time.time() - 1),  # Already expired
        )

        storage.store_access_token(access_token)
        retrieved = storage.get_access_token("expired_token")

        assert retrieved is None

    def test_revoke_token(self) -> None:
        """Test revoking an access token."""
        storage = OAuthStorage()

        access_token = AccessToken(
            token="token_to_revoke",
            client_id="test_client",
            scopes=["openid"],
            expires_at=int(time.time() + 3600),
        )

        storage.store_access_token(access_token)
        assert storage.get_access_token("token_to_revoke") is not None

        storage.revoke_token("token_to_revoke")
        assert storage.get_access_token("token_to_revoke") is None

    def test_store_and_get_client(self) -> None:
        """Test storing and retrieving a client."""
        storage = OAuthStorage()

        client = OAuthClientInformationFull(
            client_id="test_client_123",
            client_secret="secret",
            redirect_uris=[AnyUrl("http://localhost:3000/callback")],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        storage.store_client(client)
        retrieved = storage.get_client("test_client_123")

        assert retrieved is not None
        assert retrieved.client_id == "test_client_123"
        assert retrieved.client_secret == "secret"

    def test_cleanup_expired(self) -> None:
        """Test cleanup of expired tokens and codes."""
        storage = OAuthStorage()

        # Add expired authorization code
        expired_code = AuthorizationCode(
            code="expired",
            scopes=["openid"],
            expires_at=time.time() - 1,
            client_id="test_client",
            code_challenge="test_challenge",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
        )
        storage.store_authorization_code(expired_code)

        # Add valid authorization code
        valid_code = AuthorizationCode(
            code="valid",
            scopes=["openid"],
            expires_at=time.time() + 600,
            client_id="test_client",
            code_challenge="test_challenge",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
        )
        storage.store_authorization_code(valid_code)

        # Add expired access token
        expired_token = AccessToken(
            token="expired_token",
            client_id="test_client",
            scopes=["openid"],
            expires_at=int(time.time() - 1),
        )
        storage.store_access_token(expired_token)

        # Add valid access token
        valid_token = AccessToken(
            token="valid_token",
            client_id="test_client",
            scopes=["openid"],
            expires_at=int(time.time() + 3600),
        )
        storage.store_access_token(valid_token)

        # Run cleanup
        storage.cleanup_expired()

        # Expired items should be removed
        assert storage.get_authorization_code("expired") is None
        assert storage.get_access_token("expired_token") is None

        # Valid items should remain (note: get_authorization_code is single-use)
        assert storage.get_authorization_code("valid") is not None
        assert storage.get_access_token("valid_token") is not None
