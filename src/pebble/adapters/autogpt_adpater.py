"""
Adapter for Autogpt agents.

This module provides an adapter that translates between the Autogpt agent framework
and the unified pebble protocol.
For more details please visit the page : https://github.com/Significant-Gravitas/AutoGPT/tree/master

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


class AutogptAdapter(AgentProtocol):
    """Adapter for Autogpt agents."""
    
    # TODO: Implement Autogpt adapter