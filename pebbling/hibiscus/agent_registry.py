# 
# |---------------------------------------------------------|
# |                                                         |
# |                 Give Feedback / Get Help                |
# | https://github.com/Pebbling-ai/pebble/issues/new/choose |
# |                                                         |
# |---------------------------------------------------------|
#
#  Thank you users! We ❤️ you! - 🐧

"""
Agent registry integration module for registering Pebbling agents with Hibiscus registry.

This module handles agent registration with external registries, primarily Hibiscus,
allowing agents to be discovered and accessed by other systems.
"""

import asyncio
from typing import Any, Dict

from pydantic.types import SecretStr

from pebbling.common.models import AgentManifest
from pebbling.hibiscus.registry import HibiscusClient
from pebbling.utils.logging import get_logger

logger = get_logger("pebbling.hibiscus.agent_registry")

def register_with_registry(
    author: str,
    agent_manifest: AgentManifest,
    agent_registry_pat_token: SecretStr,
    agent_registry: str = "hibiscus",
    agent_registry_url: str = "http://localhost:19191",
    issue_certificate: bool = False,
    csr_data: str = None,
    certificate_validity_days: int = 365,
    **kwargs: Dict[str, Any]
):
    if agent_registry == "hibiscus":
        logger.info(f"Registering agent with Hibiscus at {agent_registry_url}")
        hibiscus_client: HibiscusClient = HibiscusClient(
            hibiscus_url=agent_registry_url,
            pat_token=agent_registry_pat_token,
            email=author
        )
        try:
            result = asyncio.run(hibiscus_client.register_agent(
                agent_manifest=agent_manifest,
                issue_certificate=issue_certificate,
                csr_data=csr_data,
                certificate_validity_days=certificate_validity_days,
                **kwargs
            ))
            
            if agent_manifest.identity and agent_manifest.identity.get('did'):
                logger.info(f"Agent registered with DID: {agent_manifest.identity.get('did')}")
            
            # Log certificate information if issued
            if issue_certificate and result.get("certificate"):
                cert_info = result["certificate"]
                logger.info(f"Certificate issued successfully - ID: {cert_info.get('certificate_id')}")
                logger.info(f"Certificate valid until: {cert_info.get('valid_until')}")
            elif issue_certificate and result.get("certificate_error"):
                logger.warning(f"Agent registered but certificate issuance failed: {result['certificate_error']}")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to register agent with Hibiscus: {str(e)}")
            raise
    elif agent_registry == "custom":
        logger.info("Using custom agent registry")
        raise ValueError("Custom agent registry not implemented yet")
    else:
        logger.error(f"Unknown agent registry: {agent_registry}")
        raise ValueError(f"Unknown agent registry: {agent_registry}")