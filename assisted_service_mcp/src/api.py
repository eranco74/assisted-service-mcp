"""FastAPI application setup for the Assisted Service MCP server.

This module initializes the FastAPI app and sets up the MCP server
with appropriate transport protocols.
"""

from starlette.requests import Request
from starlette.responses import RedirectResponse, JSONResponse
from starlette.routing import Route

from mcp.server.auth.provider import construct_redirect_uri
from assisted_service_mcp.src.mcp import AssistedServiceMCPServer
from assisted_service_mcp.src.settings import settings
from assisted_service_mcp.src.logger import log, configure_logging

# Ensure logging is configured before any module-level log usage
configure_logging()

# Initialize the MCP server
server = AssistedServiceMCPServer()

# Choose the appropriate transport protocol based on settings
if settings.TRANSPORT == "streamable-http":
    app = server.mcp.streamable_http_app()
    log.info("Using StreamableHTTP transport (stateless)")
else:
    app = server.mcp.sse_app()
    log.info("Using SSE transport (stateful)")


# Add OAuth callback route if OAuth is enabled
if settings.OAUTH_ENABLED and server.oauth_provider:

    async def oauth_callback(request: Request) -> RedirectResponse | JSONResponse:
        """Handle OAuth callback from Red Hat SSO.

        This endpoint receives the authorization code from Red Hat SSO after
        the user authenticates, exchanges it for tokens, and redirects back
        to the MCP client with an authorization code.
        """
        try:
            # Get code and state from query parameters
            code = request.query_params.get("code")
            state = request.query_params.get("state")
            error = request.query_params.get("error")

            if error:
                log.error("OAuth error from Red Hat SSO: %s", error)
                error_description = request.query_params.get(
                    "error_description", "Authentication failed"
                )
                return JSONResponse(
                    status_code=400,
                    content={"error": error, "error_description": error_description},
                )

            if not code or not state:
                log.error("Missing code or state in OAuth callback")
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "Missing code or state",
                    },
                )

            log.info("Received OAuth callback with state: %s", state)

            # Retrieve the original authorization request from storage
            original_auth = await server.oauth_provider.load_authorization_code(
                client=None,  # We'll validate after retrieving
                authorization_code=state,
            )

            if not original_auth:
                log.error("Invalid or expired state parameter")
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "invalid_request",
                        "error_description": "Invalid or expired state",
                    },
                )

            # Exchange the SSO code for tokens
            callback_url = server.oauth_provider.callback_url
            token_data = server.oauth_provider.exchange_sso_code_for_tokens(
                code, callback_url
            )

            access_token = token_data.get("access_token")
            expires_in = token_data.get("expires_in")

            if not access_token:
                log.error("No access token in SSO response")
                return JSONResponse(
                    status_code=500,
                    content={
                        "error": "server_error",
                        "error_description": "Failed to obtain access token",
                    },
                )

            log.info("Successfully obtained tokens from Red Hat SSO")

            # Create an MCP authorization code
            mcp_code = server.oauth_provider.create_mcp_authorization_code(
                client_id=original_auth.client_id,
                redirect_uri=original_auth.redirect_uri,
                code_challenge=original_auth.code_challenge,
                scopes=original_auth.scopes,
                sso_access_token=access_token,
                sso_expires_in=expires_in,
            )

            # Construct the redirect URI back to the MCP client
            redirect_uri = construct_redirect_uri(
                str(original_auth.redirect_uri),
                code=mcp_code,
                state=None,  # We stored the state in the original_auth
            )

            log.info("Redirecting to MCP client: %s", redirect_uri)
            return RedirectResponse(url=redirect_uri)

        except Exception as e:
            log.exception("Error in OAuth callback: %s", e)
            return JSONResponse(
                status_code=500,
                content={"error": "server_error", "error_description": str(e)},
            )

    # Add the callback route to the app
    app.routes.append(
        Route("/oauth/callback", endpoint=oauth_callback, methods=["GET"])
    )
    log.info("OAuth callback route registered at /oauth/callback")
