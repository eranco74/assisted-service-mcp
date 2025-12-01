"""OAuth provider implementation that proxies to Red Hat SSO."""

import secrets
import time
from typing import Optional
from urllib.parse import urlencode

import requests
from pydantic import AnyUrl

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from assisted_service_mcp.src.logger import log
from assisted_service_mcp.src.oauth.storage import OAuthStorage
from assisted_service_mcp.src.settings import get_setting


class RedHatSSOProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """OAuth provider that proxies authentication to Red Hat SSO.

    This provider implements the MCP OAuth flow by redirecting to Red Hat SSO
    for authentication, then proxying the tokens back to the MCP client.
    """

    def __init__(self, storage: OAuthStorage, callback_url: str) -> None:
        """Initialize the Red Hat SSO provider.

        Args:
            storage: The OAuth storage instance for tokens and codes.
            callback_url: The callback URL where Red Hat SSO will redirect after auth.
        """
        self.storage = storage
        self.callback_url = callback_url
        self.sso_auth_url = get_setting("SSO_AUTH_URL")
        self.sso_token_url = get_setting("SSO_URL")
        self.sso_client_id = get_setting("OAUTH_CLIENT_ID")

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        """Get client information by client ID.

        Since the MCP client handles registration, we accept any client and
        return minimal client information.

        Args:
            client_id: The client ID to look up.

        Returns:
            Client information if the client has registered, None otherwise.
        """
        # Check if client is already stored (from dynamic registration)
        client = self.storage.get_client(client_id)
        if client:
            return client

        # For clients that haven't registered yet, return None
        # The MCP framework will handle dynamic registration if enabled
        return None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register a new client.

        Args:
            client_info: The client information to register.
        """
        log.info("Registering OAuth client: %s", client_info.client_id)
        self.storage.store_client(client_info)

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Initiate the authorization flow by redirecting to Red Hat SSO.

        This creates a state parameter that includes the MCP client's redirect_uri
        and code_challenge, then redirects to Red Hat SSO for authentication.

        Args:
            client: The client requesting authorization.
            params: Authorization parameters including redirect_uri and code_challenge.

        Returns:
            URL to redirect the user to for authentication.

        Raises:
            AuthorizeError: If the authorization request is invalid.
        """
        log.info("Starting OAuth authorization flow for client: %s", client.client_id)

        # Create a random state token for the SSO flow
        # The state will be used to retrieve the original authorization request
        state_token = secrets.token_urlsafe(32)

        # Store the state in an authorization code temporarily (reusing the structure)
        # This will be retrieved in the callback
        temp_code = AuthorizationCode(
            code=state_token,
            scopes=params.scopes or [],
            expires_at=time.time() + 600,  # 10 minutes
            client_id=client.client_id or "",
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        self.storage.store_authorization_code(temp_code)

        # Build Red Hat SSO authorization URL
        sso_params = {
            "client_id": self.sso_client_id,
            "response_type": "code",
            "redirect_uri": self.callback_url,
            "state": state_token,
            "scope": " ".join(params.scopes) if params.scopes else "openid",
        }

        auth_url = f"{self.sso_auth_url}?{urlencode(sso_params)}"
        log.debug("Redirecting to Red Hat SSO: %s", auth_url)

        return auth_url

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[AuthorizationCode]:
        """Load an authorization code.

        Args:
            client: The client requesting the code.
            authorization_code: The authorization code string.

        Returns:
            The AuthorizationCode if found and valid, None otherwise.
        """
        code = self.storage.get_authorization_code(authorization_code)
        if code and code.client_id == client.client_id:
            return code
        return None

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange an authorization code for tokens.

        This is called by the MCP client after it receives the authorization code.
        The authorization code should already contain the Red Hat SSO tokens
        that were stored during the callback.

        Args:
            client: The client exchanging the code.
            authorization_code: The authorization code to exchange.

        Returns:
            OAuth token with access and refresh tokens.

        Raises:
            TokenError: If the exchange fails.
        """
        log.info("Exchanging authorization code for client: %s", client.client_id)

        # The authorization code should have the tokens stored in its code field
        # This was done in the callback handler
        # For now, we expect the callback to have stored the actual tokens
        # in a special format in the code

        # Retrieve the SSO token that was stored for this authorization code
        actual_access_token = self.storage.get_sso_token_for_code(
            authorization_code.code
        )

        if not actual_access_token:
            log.error("Failed to find tokens for authorization code")
            raise TokenError(
                error="invalid_grant",
                error_description="Authorization code is invalid or expired",
            )

        # Store the SSO token as an access token for validation
        expires_at = None
        if authorization_code.expires_at:
            expires_at = int(authorization_code.expires_at + 3600)  # 1 hour from now

        # Store the access token for validation
        validation_token = AccessToken(
            token=actual_access_token,
            client_id=client.client_id or "",
            scopes=authorization_code.scopes,
            expires_at=expires_at,
            resource=authorization_code.resource,
        )
        self.storage.store_access_token(validation_token)

        # Calculate expires_in
        expires_in = None
        if expires_at:
            expires_in = int(expires_at - time.time())
            if expires_in < 0:
                expires_in = 0

        return OAuthToken(
            access_token=actual_access_token,
            token_type="Bearer",
            expires_in=expires_in,
            scope=(
                " ".join(authorization_code.scopes)
                if authorization_code.scopes
                else None
            ),
            refresh_token=None,  # Client handles refresh directly with Red Hat SSO
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Optional[RefreshToken]:
        """Load a refresh token.

        Since the MCP client handles token refresh directly with Red Hat SSO,
        this method returns None.

        Args:
            client: The client requesting the refresh token.
            refresh_token: The refresh token string.

        Returns:
            None, as refresh is handled by the client.
        """
        # Client handles refresh directly with Red Hat SSO
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange a refresh token for new tokens.

        Since the MCP client handles token refresh directly with Red Hat SSO,
        this method raises an error.

        Args:
            client: The client exchanging the refresh token.
            refresh_token: The refresh token to exchange.
            scopes: Requested scopes.

        Returns:
            OAuth token with new access and refresh tokens.

        Raises:
            TokenError: Always, as refresh is handled by the client.
        """
        # Client handles refresh directly with Red Hat SSO
        raise TokenError(
            error="unsupported_grant_type",
            error_description="Token refresh is handled directly with Red Hat SSO",
        )

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        """Load and validate an access token.

        Args:
            token: The access token to validate.

        Returns:
            AccessToken if valid, None otherwise.
        """
        return self.storage.get_access_token(token)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Revoke a token.

        Args:
            token: The token to revoke.
        """
        log.info("Revoking token")
        self.storage.revoke_token(token.token)

    def exchange_sso_code_for_tokens(self, code: str, redirect_uri: str) -> dict:
        """Exchange Red Hat SSO authorization code for tokens.

        This is called from the callback handler after Red Hat SSO redirects back.

        Args:
            code: The authorization code from Red Hat SSO.
            redirect_uri: The redirect URI used in the original request.

        Returns:
            Dictionary containing the token response from Red Hat SSO.

        Raises:
            RuntimeError: If the token exchange fails.
        """
        log.info("Exchanging Red Hat SSO code for tokens")

        token_params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.sso_client_id,
        }

        try:
            response = requests.post(self.sso_token_url, data=token_params, timeout=30)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            log.error("Failed to exchange SSO code for tokens: %s", e)
            raise RuntimeError(f"Failed to obtain tokens from Red Hat SSO: {e}") from e

        try:
            token_data = response.json()
            if "access_token" not in token_data:
                raise ValueError("Missing access_token in response")
            return token_data
        except (ValueError, KeyError) as e:
            log.error("Invalid SSO token response: %s", e)
            raise RuntimeError("Invalid token response from Red Hat SSO") from e

    def create_mcp_authorization_code(
        self,
        client_id: str,
        redirect_uri: AnyUrl,
        code_challenge: str,
        scopes: list[str],
        sso_access_token: str,
        sso_expires_in: Optional[int],
    ) -> str:
        """Create an MCP authorization code after successful SSO authentication.

        Args:
            client_id: The MCP client ID.
            redirect_uri: The MCP client's redirect URI.
            code_challenge: The PKCE code challenge.
            scopes: Requested scopes.
            sso_access_token: The access token from Red Hat SSO.
            sso_expires_in: Token expiry time in seconds.

        Returns:
            The MCP authorization code string.
        """
        # Generate a new authorization code for the MCP client
        mcp_code = secrets.token_urlsafe(32)

        # Store the authorization code
        auth_code = AuthorizationCode(
            code=mcp_code,
            scopes=scopes,
            expires_at=time.time() + 300,  # 5 minutes for code exchange
            client_id=client_id,
            code_challenge=code_challenge,
            redirect_uri=redirect_uri,
            redirect_uri_provided_explicitly=True,
        )
        self.storage.store_authorization_code(auth_code)

        # Store the SSO token mapping for the authorization code
        self.storage.store_sso_token_for_code(mcp_code, sso_access_token)

        log.debug("Created MCP authorization code for client: %s", client_id)
        return mcp_code
