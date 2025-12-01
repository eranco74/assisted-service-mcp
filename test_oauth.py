#!/usr/bin/env python3
"""Test program to validate OAuth functionality.

This script tests the OAuth implementation by:
1. Initializing the server with OAuth enabled
2. Simulating the OAuth flow
3. Validating token storage and retrieval
"""

import asyncio
import os
from pydantic import AnyUrl

from assisted_service_mcp.src.oauth import RedHatSSOProvider, OAuthStorage
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull


def print_status(message, success=True):
    """Print colored status message."""
    color = "\033[92m" if success else "\033[91m"  # Green or Red
    reset = "\033[0m"
    symbol = "✓" if success else "✗"
    print(f"{color}{symbol} {message}{reset}")


async def test_oauth_provider():
    """Test OAuth provider functionality."""
    print("\n" + "=" * 60)
    print("Testing OAuth Provider Functionality")
    print("=" * 60 + "\n")

    # Step 1: Initialize storage and provider
    print("1. Initializing OAuth storage and provider...")
    storage = OAuthStorage()
    callback_url = "http://localhost:8000/oauth/callback"
    provider = RedHatSSOProvider(storage, callback_url)
    print_status("OAuth provider initialized successfully")

    # Step 2: Create a test client
    print("\n2. Creating test OAuth client...")
    test_client = OAuthClientInformationFull(
        client_id="test_client_12345",
        client_secret="test_secret",
        redirect_uris=[AnyUrl("http://localhost:3000/callback")],
        grant_types=["authorization_code"],
        response_types=["code"],
    )
    await provider.register_client(test_client)
    print_status(f"Client registered with ID: {test_client.client_id}")

    # Step 3: Test authorization flow initiation
    print("\n3. Initiating authorization flow...")
    auth_params = AuthorizationParams(
        state="test_state_123",
        scopes=["openid", "profile"],
        code_challenge="test_code_challenge_value",
        redirect_uri=AnyUrl("http://localhost:3000/callback"),
        redirect_uri_provided_explicitly=True,
    )
    redirect_url = await provider.authorize(test_client, auth_params)
    print_status("Authorization redirect URL generated")
    print(f"  Redirect URL: {redirect_url[:80]}...")

    # Step 4: Simulate SSO callback - create MCP authorization code
    print("\n4. Simulating SSO callback...")
    sso_token = "mock_sso_access_token_abcdefg123456"
    mcp_code = provider.create_mcp_authorization_code(
        client_id=test_client.client_id or "",
        redirect_uri=test_client.redirect_uris[0],
        code_challenge=auth_params.code_challenge,
        scopes=auth_params.scopes or [],
        sso_access_token=sso_token,
        sso_expires_in=3600,
    )
    print_status("MCP authorization code created")
    print(f"  Authorization code: {mcp_code[:20]}...")

    # Step 5: Exchange authorization code for tokens
    print("\n5. Exchanging authorization code for tokens...")
    auth_code_obj = storage.get_authorization_code(mcp_code)
    if auth_code_obj is None:
        print_status("Failed to retrieve authorization code", success=False)
        return False

    oauth_token = await provider.exchange_authorization_code(
        test_client, auth_code_obj
    )
    print_status("Authorization code exchanged successfully")
    print(f"  Access token: {oauth_token.access_token[:20]}...")
    print(f"  Token type: {oauth_token.token_type}")
    print(f"  Expires in: {oauth_token.expires_in}s")

    # Step 6: Validate access token
    print("\n6. Validating access token...")
    loaded_token = await provider.load_access_token(oauth_token.access_token)
    if loaded_token is None:
        print_status("Token validation failed", success=False)
        return False

    print_status("Access token validated successfully")
    print(f"  Client ID: {loaded_token.client_id}")
    print(f"  Scopes: {', '.join(loaded_token.scopes)}")

    # Step 7: Test token revocation
    print("\n7. Testing token revocation...")
    await provider.revoke_token(loaded_token)
    revoked_token = await provider.load_access_token(oauth_token.access_token)
    if revoked_token is not None:
        print_status("Token revocation failed", success=False)
        return False

    print_status("Token revoked successfully")

    # Step 8: Summary
    print("\n8. OAuth Flow Summary:")
    print("  ✓ Authorization URL generation")
    print("  ✓ Authorization code creation and storage")
    print("  ✓ Token exchange (code -> access token)")
    print("  ✓ Token validation")
    print("  ✓ Token revocation")
    print("\nNote: Server initialization with OAuth is tested in unit tests")

    print("\n" + "=" * 60)
    print("✅ All OAuth tests passed successfully!")
    print("=" * 60 + "\n")

    return True


def main():
    """Main entry point."""
    try:
        # Set up environment for testing
        os.environ["MCP_HOST"] = "localhost"
        os.environ["MCP_PORT"] = "8000"
        os.environ["TRANSPORT"] = "streamable-http"

        # Run async tests
        success = asyncio.run(test_oauth_provider())

        if success:
            print("\n🎉 OAuth implementation is working correctly!")
            print("\nNext steps:")
            print("  1. Set OAUTH_ENABLED=true in your environment")
            print("  2. Start the server with: make run-local")
            print("  3. Configure your MCP client to connect")
            return 0
        else:
            print("\n❌ Some OAuth tests failed")
            return 1

    except Exception as e:
        print(f"\n❌ Error during OAuth testing: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())

