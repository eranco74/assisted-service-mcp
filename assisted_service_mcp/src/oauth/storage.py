"""In-memory storage for OAuth tokens and authorization codes."""

import time
from typing import Dict, Optional

from mcp.server.auth.provider import AuthorizationCode, AccessToken
from mcp.shared.auth import OAuthClientInformationFull


class OAuthStorage:
    """Simple in-memory storage for OAuth authorization codes and access tokens.

    Note: This is a minimal implementation. For production use, consider using
    a persistent storage backend with proper expiration and cleanup.
    """

    def __init__(self) -> None:
        """Initialize the OAuth storage."""
        # Store authorization codes: code -> AuthorizationCode
        self._authorization_codes: Dict[str, AuthorizationCode] = {}

        # Store access tokens: token -> AccessToken
        self._access_tokens: Dict[str, AccessToken] = {}

        # Store registered clients: client_id -> OAuthClientInformationFull
        self._clients: Dict[str, OAuthClientInformationFull] = {}

        # Map authorization codes to their SSO tokens: auth_code -> sso_token
        self._code_to_sso_token: Dict[str, str] = {}

    def store_authorization_code(self, auth_code: AuthorizationCode) -> None:
        """Store an authorization code.

        Args:
            auth_code: The authorization code to store.
        """
        self._authorization_codes[auth_code.code] = auth_code

    def get_authorization_code(self, code: str) -> Optional[AuthorizationCode]:
        """Retrieve and remove an authorization code.

        Authorization codes are single-use, so they are removed after retrieval.

        Args:
            code: The authorization code string.

        Returns:
            The AuthorizationCode if found and not expired, None otherwise.
        """
        auth_code = self._authorization_codes.pop(code, None)
        if auth_code is None:
            return None

        # Check if the code has expired
        if auth_code.expires_at < time.time():
            # Also remove the mapping
            self._code_to_sso_token.pop(code, None)
            return None

        return auth_code

    def store_sso_token_for_code(self, auth_code: str, sso_token: str) -> None:
        """Store SSO token mapping for an authorization code.

        Args:
            auth_code: The authorization code.
            sso_token: The SSO access token.
        """
        self._code_to_sso_token[auth_code] = sso_token

    def get_sso_token_for_code(self, auth_code: str) -> Optional[str]:
        """Retrieve and remove SSO token for an authorization code.

        Args:
            auth_code: The authorization code.

        Returns:
            The SSO token if found, None otherwise.
        """
        return self._code_to_sso_token.pop(auth_code, None)

    def store_access_token(self, access_token: AccessToken) -> None:
        """Store an access token.

        Args:
            access_token: The access token to store.
        """
        self._access_tokens[access_token.token] = access_token

    def get_access_token(self, token: str) -> Optional[AccessToken]:
        """Retrieve an access token.

        Args:
            token: The access token string.

        Returns:
            The AccessToken if found and not expired, None otherwise.
        """
        access_token = self._access_tokens.get(token)
        if access_token is None:
            return None

        # Check if the token has expired
        if (
            access_token.expires_at is not None
            and access_token.expires_at < time.time()
        ):
            # Remove expired token
            self._access_tokens.pop(token, None)
            return None

        return access_token

    def revoke_token(self, token: str) -> None:
        """Revoke an access token.

        Args:
            token: The access token string to revoke.
        """
        self._access_tokens.pop(token, None)

    def store_client(self, client: OAuthClientInformationFull) -> None:
        """Store a registered client.

        Args:
            client: The client information to store.
        """
        if client.client_id:
            self._clients[client.client_id] = client

    def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        """Retrieve a registered client.

        Args:
            client_id: The client ID to look up.

        Returns:
            The client information if found, None otherwise.
        """
        return self._clients.get(client_id)

    def cleanup_expired(self) -> None:
        """Remove expired authorization codes and access tokens.

        This should be called periodically to prevent memory leaks.
        """
        current_time = time.time()

        # Clean up expired authorization codes
        expired_codes = [
            code
            for code, auth_code in self._authorization_codes.items()
            if auth_code.expires_at < current_time
        ]
        for code in expired_codes:
            self._authorization_codes.pop(code, None)

        # Clean up expired access tokens
        expired_tokens = [
            token
            for token, access_token in self._access_tokens.items()
            if access_token.expires_at is not None
            and access_token.expires_at < current_time
        ]
        for token in expired_tokens:
            self._access_tokens.pop(token, None)
