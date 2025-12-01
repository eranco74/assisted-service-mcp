"""Tests for OAuth provider."""

import time
from unittest.mock import Mock, patch, MagicMock
from pydantic import AnyUrl
import pytest

from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull

from assisted_service_mcp.src.oauth.provider import RedHatSSOProvider
from assisted_service_mcp.src.oauth.storage import OAuthStorage


@pytest.fixture
def oauth_storage() -> OAuthStorage:
    """Create an OAuth storage instance."""
    return OAuthStorage()


@pytest.fixture
def oauth_provider(oauth_storage: OAuthStorage) -> RedHatSSOProvider:
    """Create an OAuth provider instance."""
    return RedHatSSOProvider(
        storage=oauth_storage,
        callback_url="http://localhost:8000/oauth/callback",
    )


@pytest.fixture
def test_client() -> OAuthClientInformationFull:
    """Create a test OAuth client."""
    return OAuthClientInformationFull(
        client_id="test_client",
        client_secret="test_secret",
        redirect_uris=[AnyUrl("http://localhost:3000/callback")],
        grant_types=["authorization_code"],
        response_types=["code"],
    )


class TestRedHatSSOProvider:
    """Test cases for RedHatSSOProvider."""

    @pytest.mark.asyncio
    async def test_register_client(
        self, oauth_provider: RedHatSSOProvider, test_client: OAuthClientInformationFull
    ) -> None:
        """Test client registration."""
        await oauth_provider.register_client(test_client)

        retrieved = await oauth_provider.get_client("test_client")
        assert retrieved is not None
        assert retrieved.client_id == "test_client"

    @pytest.mark.asyncio
    async def test_authorize_creates_redirect_url(
        self,
        oauth_provider: RedHatSSOProvider,
        test_client: OAuthClientInformationFull,
    ) -> None:
        """Test that authorize creates a redirect URL to Red Hat SSO."""
        params = AuthorizationParams(
            state="client_state",
            scopes=["openid", "profile"],
            code_challenge="test_challenge",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
        )

        redirect_url = await oauth_provider.authorize(test_client, params)

        assert redirect_url.startswith(oauth_provider.sso_auth_url)
        assert "client_id=" in redirect_url
        assert "response_type=code" in redirect_url
        assert "redirect_uri=" in redirect_url
        assert "state=" in redirect_url

    @pytest.mark.asyncio
    async def test_load_authorization_code(
        self,
        oauth_provider: RedHatSSOProvider,
        oauth_storage: OAuthStorage,
        test_client: OAuthClientInformationFull,
    ) -> None:
        """Test loading an authorization code."""
        auth_code = AuthorizationCode(
            code="test_code",
            scopes=["openid"],
            expires_at=time.time() + 600,
            client_id="test_client",
            code_challenge="test_challenge",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
        )
        oauth_storage.store_authorization_code(auth_code)

        loaded = await oauth_provider.load_authorization_code(test_client, "test_code")

        assert loaded is not None
        assert loaded.code == "test_code"
        assert loaded.client_id == "test_client"

    @pytest.mark.asyncio
    async def test_load_authorization_code_wrong_client(
        self,
        oauth_provider: RedHatSSOProvider,
        oauth_storage: OAuthStorage,
        test_client: OAuthClientInformationFull,
    ) -> None:
        """Test loading an authorization code with wrong client ID."""
        auth_code = AuthorizationCode(
            code="test_code",
            scopes=["openid"],
            expires_at=time.time() + 600,
            client_id="different_client",
            code_challenge="test_challenge",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
        )
        oauth_storage.store_authorization_code(auth_code)

        loaded = await oauth_provider.load_authorization_code(test_client, "test_code")

        assert loaded is None

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_success(
        self,
        oauth_provider: RedHatSSOProvider,
        test_client: OAuthClientInformationFull,
    ) -> None:
        """Test exchanging an authorization code for tokens."""
        # Use the provider's method to create an MCP code with stored tokens
        # This ensures the storage format matches what the provider expects
        sso_token = "sso_access_token_xyz"
        mcp_code = oauth_provider.create_mcp_authorization_code(
            client_id="test_client",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            code_challenge="test_challenge",
            scopes=["openid", "profile"],
            sso_access_token=sso_token,
            sso_expires_in=3600,
        )

        # Retrieve the authorization code
        auth_code = oauth_provider.storage.get_authorization_code(mcp_code)
        assert auth_code is not None

        # Exchange the code
        oauth_token = await oauth_provider.exchange_authorization_code(
            test_client, auth_code
        )

        assert oauth_token.access_token == sso_token
        assert oauth_token.token_type == "Bearer"
        assert oauth_token.expires_in is not None
        assert oauth_token.expires_in > 0

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_invalid(
        self,
        oauth_provider: RedHatSSOProvider,
        test_client: OAuthClientInformationFull,
    ) -> None:
        """Test exchanging an invalid authorization code."""
        auth_code = AuthorizationCode(
            code="invalid_code",
            scopes=["openid"],
            expires_at=time.time() + 300,
            client_id="test_client",
            code_challenge="test_challenge",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
        )

        with pytest.raises(TokenError) as exc_info:
            await oauth_provider.exchange_authorization_code(test_client, auth_code)

        assert exc_info.value.error == "invalid_grant"

    @pytest.mark.asyncio
    async def test_load_access_token(
        self,
        oauth_provider: RedHatSSOProvider,
        oauth_storage: OAuthStorage,
    ) -> None:
        """Test loading an access token."""
        from mcp.server.auth.provider import AccessToken

        access_token = AccessToken(
            token="test_token",
            client_id="test_client",
            scopes=["openid"],
            expires_at=int(time.time() + 3600),
        )
        oauth_storage.store_access_token(access_token)

        loaded = await oauth_provider.load_access_token("test_token")

        assert loaded is not None
        assert loaded.token == "test_token"

    @pytest.mark.asyncio
    async def test_revoke_token(
        self,
        oauth_provider: RedHatSSOProvider,
        oauth_storage: OAuthStorage,
    ) -> None:
        """Test revoking a token."""
        from mcp.server.auth.provider import AccessToken

        access_token = AccessToken(
            token="token_to_revoke",
            client_id="test_client",
            scopes=["openid"],
            expires_at=int(time.time() + 3600),
        )
        oauth_storage.store_access_token(access_token)

        await oauth_provider.revoke_token(access_token)

        loaded = await oauth_provider.load_access_token("token_to_revoke")
        assert loaded is None

    @pytest.mark.asyncio
    async def test_exchange_refresh_token_not_supported(
        self,
        oauth_provider: RedHatSSOProvider,
        test_client: OAuthClientInformationFull,
    ) -> None:
        """Test that refresh token exchange is not supported."""
        from mcp.server.auth.provider import RefreshToken

        refresh_token = RefreshToken(
            token="refresh_token",
            client_id="test_client",
            scopes=["openid"],
        )

        with pytest.raises(TokenError) as exc_info:
            await oauth_provider.exchange_refresh_token(
                test_client, refresh_token, ["openid"]
            )

        assert exc_info.value.error == "unsupported_grant_type"

    @patch("assisted_service_mcp.src.oauth.provider.requests.post")
    def test_exchange_sso_code_for_tokens_success(
        self,
        mock_post: Mock,
        oauth_provider: RedHatSSOProvider,
    ) -> None:
        """Test exchanging SSO code for tokens."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "access_token": "sso_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "sso_refresh_token",
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        token_data = oauth_provider.exchange_sso_code_for_tokens(
            code="sso_code",
            redirect_uri="http://localhost:8000/oauth/callback",
        )

        assert token_data["access_token"] == "sso_access_token"
        assert token_data["expires_in"] == 3600
        assert mock_post.called

    @patch("assisted_service_mcp.src.oauth.provider.requests.post")
    def test_exchange_sso_code_for_tokens_failure(
        self,
        mock_post: Mock,
        oauth_provider: RedHatSSOProvider,
    ) -> None:
        """Test exchanging SSO code for tokens with failure."""
        # Mock failed response with requests exception
        import requests

        mock_post.side_effect = requests.exceptions.RequestException("Network error")

        with pytest.raises(RuntimeError) as exc_info:
            oauth_provider.exchange_sso_code_for_tokens(
                code="sso_code",
                redirect_uri="http://localhost:8000/oauth/callback",
            )

        assert "Failed to obtain tokens from Red Hat SSO" in str(exc_info.value)

    def test_create_mcp_authorization_code(
        self,
        oauth_provider: RedHatSSOProvider,
    ) -> None:
        """Test creating an MCP authorization code."""
        sso_token = "sso_token_xyz"
        mcp_code = oauth_provider.create_mcp_authorization_code(
            client_id="test_client",
            redirect_uri=AnyUrl("http://localhost:3000/callback"),
            code_challenge="test_challenge",
            scopes=["openid", "profile"],
            sso_access_token=sso_token,
            sso_expires_in=3600,
        )

        assert mcp_code is not None
        assert len(mcp_code) > 0

        # Verify the authorization code was stored using the provider's storage
        auth_code = oauth_provider.storage.get_authorization_code(mcp_code)
        assert auth_code is not None
        assert auth_code.client_id == "test_client"

        # Verify the SSO token was stored with the authorization code
        stored_sso_token = oauth_provider.storage.get_sso_token_for_code(mcp_code)
        assert stored_sso_token == sso_token
