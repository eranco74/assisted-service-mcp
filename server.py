# server.py
from typing import Dict, Any, Optional
from mcp.server.fastmcp import FastMCP
from ailib import AssistedClient
import asyncio
import os
import logging
from logging.handlers import RotatingFileHandler
import sys
from pathlib import Path

# Create logs directory if it doesn't exist
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

# Not required when using SSE transport
# for handler in logging.root.handlers[:]:
#     logging.root.removeHandler(handler)
# logging.getLogger("urllib3").setLevel(logging.WARNING)
# logging.getLogger("httpx").setLevel(logging.WARNING)
# logging.getLogger("requests").setLevel(logging.WARNING)
# logging.getLogger("asyncio").setLevel(logging.WARNING)
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            filename=log_dir / "assisted-service-mcp.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
    ],
    force=True
)
logger = logging.getLogger("assisted-service-mcp")

# Constants
API_URL = "https://api.openshift.com"
DEBUG_MODE = True


# Create an MCP server
mcp = FastMCP("Assisted", host="127.0.0.1", port=8070)

# Get offline token from environment variable
offlinetoken = os.getenv("OFFLINE_TOKEN")
if not offlinetoken:
    raise ValueError("OFFLINE_TOKEN environment variable is not set")

try:
    ai = AssistedClient(API_URL, token=None, offlinetoken=offlinetoken, debug=DEBUG_MODE, ca=None, cert=None)
    logger.info("Successfully initialized AssistedClient")
except Exception as e:
    logger.error(f"Failed to initialize AssistedClient: {str(e)}")
    raise

async def handle_api_call(func, *args, **kwargs) -> str:
    """Helper function to handle API calls with error handling"""
    try:
        logger.info(f"Calling {func.__name__} with args: {args}, kwargs: {kwargs}")
        result = await asyncio.to_thread(func, *args, **kwargs)
        logger.info(f"result is: {result}")
        return str(result)
    except asyncio.TimeoutError:
        error_msg = "Operation timed out"
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Unexpected error in {func.__name__}: {str(e)}"
        logger.error(error_msg)
        return error_msg

@mcp.tool(description="list openshift clusters")
async def list_clusters() -> str:
    """List all OpenShift clusters in the assisted service"""
    logger.info("Listing clusters")
    return await handle_api_call(ai.list_clusters)

@mcp.tool(description="list openshift cluster events")
async def list_events(cluster_name: str) -> str:
    """List events for a specific OpenShift cluster

    Args:
        cluster_name: Name of the cluster to list events for
    """
    logger.info(f"Listing events for cluster: {cluster_name}")
    return await handle_api_call(ai.list_events, cluster_name)

@mcp.tool(description="list openshift cluster manifests")
async def list_manifests(cluster_name: str) -> str:
    """List manifests for a specific OpenShift cluster

    Args:
        cluster_name: Name of the cluster to list manifests for
    """
    logger.info(f"Listing manifests for cluster: {cluster_name}")
    return await handle_api_call(ai.list_manifests, cluster_name)

@mcp.tool(description="create a new openshift cluster")
async def create_cluster(cluster_name=None, high_availability_mode='Full', openshift_version=None, base_dns_domain=None, cluster_network_cidr='10.128.0.0/14', pull_secret=None, ssh_public_key=None) -> str:
    """Create a new OpenShift cluster

    Args:
        cluster_name: Name of the cluster to create
        high_availability_mode: High availability mode for the cluster can be 'Full' or 'None'
        openshift_version: Version of OpenShift to install
        base_dns_domain: Base DNS domain for the cluster
        cluster_network_cidr: Cluster network CIDR
        pull_secret: Pull secret for the cluster
        ssh_public_key: SSH public key for the cluster
    """
    logger.info(f"Creating cluster: {cluster_name}, base_dns_domain: {base_dns_domain}, version: {openshift_version}, high_availability_mode: {high_availability_mode}")
    return await handle_api_call(ai.create_cluster, overrides=dict(cluster_name, base_dns_domain=base_dns_domain, openshift_version=openshift_version, high_availability_mode=high_availability_mode))

@mcp.tool(description="delete an openshift cluster")
async def delete_cluster(cluster_name: str) -> str:
    """Delete an OpenShift cluster

    Args:
        cluster_name: Name of the cluster to delete
    """
    logger.info(f"Deleting cluster: {cluster_name}")
    return await handle_api_call(ai.delete_cluster, cluster_name)

@mcp.tool(description="get information about an openshift cluster")
async def cluster_info(cluster_name: str) -> str:
    """Get detailed information about an OpenShift cluster

    Args:
        cluster_name: Name of the cluster to get information for
    """
    logger.info(f"Getting info for cluster: {cluster_name}")
    return await handle_api_call(ai.get_cluster, cluster_name)

@mcp.tool(description="update an openshift cluster")
async def update_cluster(cluster_name: str, ) -> str:
    """Update an OpenShift cluster's configuration

    Args:
        cluster_name: Name of the cluster to update
    """
    logger.info(f"Updating cluster: {cluster_name}")
    return await handle_api_call(ai.update_cluster, cluster_name, )

@mcp.tool(description="create manifests for an openshift cluster")
async def create_manifests(cluster_name: str, directory, openshift=False) -> str:
    """Create manifests for an OpenShift cluster

    Args:
        cluster_name: Name of the cluster to create manifests for
        directory: Directory containing the manifests
        openshift: Whether to create OpenShift manifests
    """
    logger.info(f"Creating manifests for cluster: {cluster_name}")
    return await handle_api_call(ai.upload_manifests, cluster_name,  directory, openshift=False)

@mcp.tool(description="delete manifests for an openshift cluster")
async def delete_manifests(cluster_name: str) -> str:
    """Delete manifests for an OpenShift cluster

    Args:
        cluster_name: Name of the cluster to delete manifests for
    """
    logger.info(f"Deleting manifests for cluster: {cluster_name}")
    return await handle_api_call(ai.delete_manifests, cluster_name)

if __name__ == "__main__":
    try:
        logger.info("Starting MCP server...")
        mcp.run(transport="sse")
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server crashed with error: {str(e)}", exc_info=True)
        raise
