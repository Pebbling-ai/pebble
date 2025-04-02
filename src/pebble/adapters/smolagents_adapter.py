"""
Adapter for SmolAgents agents.

This module provides an adapter that translates between the SmolAgents agent framework
and the unified pebble protocol.
For more details please visit the page : https://github.com/huggingface/smolagents/tree/main/src/smolagents

"""
import base64
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

import httpx

from pebble.core.protocol import AgentProtocol
from pebble.schemas.models import (
    ActionRequest,
    ActionResponse,
    MessageRole,
    ImageArtifact,
    ListenRequest,
    VideoArtifact,
    ViewRequest
)


class SmolAgentsAdapter(AgentProtocol):
    """Adapter for SmolAgents agents."""
    
    # TODO: Implement SmolAgents adapter