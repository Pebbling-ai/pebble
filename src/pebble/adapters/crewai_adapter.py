"""
Adapter for CrewAI agents.

This module provides an adapter that translates between the CrewAI agent framework
and the unified pebble protocol.
For more details please visit the page : https://github.com/crewAIInc/crewAI/tree/main/src/crewai/agents

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


class CrewAIAdapter(AgentProtocol):
    """Adapter for CrewAI agents."""
    
    # TODO: Implement CrewAI adapter