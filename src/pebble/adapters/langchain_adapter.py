"""
Adapter for LangChain agents.

This module provides an adapter that translates between the LangChain agent framework
and the unified pebble protocol.
For more details please visit the page : https://python.langchain.com/v0.1/docs/modules/agents/quick_start/

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


class LangChainAdapter(AgentProtocol):
    """Adapter for LangChain agents."""
    
    # TODO: Implement LangChain adapter