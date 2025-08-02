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
Pebblify decorator for transforming regular agents into secure, networked Pebble agents.

This module provides the core decorator that handles:
1. Protocol-compliant function wrapping with AgentAdapter
2. Key generation and DID document creation
3. Certificate management via Sheldon
4. Secure server setup with MLTS
5. Agent registration with Hibiscus
6. Runner registration for execution
"""

import functools
import inspect
import uuid
from typing import Any, Callable, Dict, List, Optional, Union

from pebbling.protocol.types import (
    AgentCapabilities, 
    AgentManifest, 
    AgentSkill, 
)
from pebbling.common.models.models import ( 
    SecurityConfig, 
    AgentRegistrationConfig, 
    CAConfig, 
    DeploymentConfig,
    SecuritySetupResult
)
from pebbling.security.setup_security import create_security_config
from pebbling.penguin.manifest import validate_agent_function, create_manifest

# Import logging from pebbling utils
from pebbling.utils.logging import get_logger

# Configure logging for the module
logger = get_logger("pebbling.agent.pebblify")

def pebblify(
    name: Optional[str] = None,
    id: Optional[str] = None,
    version: str = "1.0.0",
    skill: Optional[AgentSkill] = None,
    capabilities: Optional[AgentCapabilities] = None,
    security_config: SecurityConfig = None,  
    registration_config: Optional[AgentRegistrationConfig] = None,
    ca_config: Optional[CAConfig] = None,
    deployment_config: Optional[DeploymentConfig] = None,
    
) -> Callable:
    """Transform a protocol-compliant function into a Pebbling-compatible agent.
    
    """
    def decorator(agent_function: Callable) -> AgentManifest:
        # Validate that this is a protocol-compliant function
        validate_agent_function(agent_function)

        agent_id = id or uuid.uuid4().hex

        security_setup_result: SecuritySetupResult = create_security_config(
            id=agent_id,
            did_required=security_config.did_required,
            recreate_keys=security_config.recreate_keys,
            require_challenge_response=security_config.require_challenge_response,
            create_csr=security_config.create_csr,
            verify_requests=security_config.verify_requests,
            allow_anonymous=security_config.allow_anonymous
        )
       
        # Extract security and identity from setup result
        security = security_setup_result.security_config
        identity = security_setup_result.identity

        _manifest = create_manifest(
            agent_function=agent_function,
            name=name,
            id=agent_id,
            description=None,
            skills=[skill] if skill else None,
            capabilities=capabilities,
            version=version,
            extra_metadata=None,
            security=security,
            identity=identity
        )

        

        print(_manifest)
            
        return _manifest
    return decorator