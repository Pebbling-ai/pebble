"""
Adapter for LlamaIndex agents.

This module provides an adapter that translates between the LlamaIndex agent framework
and the unified pebble protocol.
For more details please visit the page : https://docs.llamaindex.ai/en/stable/use_cases/agents/

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


class LlamaIndexAdapter(AgentProtocol):
    """Adapter for LlamaIndex agents."""
    
    # TODO: Implement LlamaIndex adapter