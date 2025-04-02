"""
Adapter for Autogen agents.

This module provides an adapter that translates between the Autogen agent framework
and the unified pebble protocol.
For more details please visit the page : https://github.com/microsoft/autogen

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


class AutogenAdapter(AgentProtocol):
    """Adapter for Autogen agents."""
    
    # TODO: Implement Autogen adapter