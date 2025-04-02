"""
Adapter for Agno agents.

This module provides an adapter that translates between the Agno agent framework
and the unified pebble protocol.
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


class AgnoAdapter(AgentProtocol):
    """Adapter for Agno agents."""
    
    def __init__(self, 
                 agent, 
                 agent_id: Optional[UUID] = None, 
                 name: Optional[str] = None, 
                 metadata: Optional[Dict[str, Any]] = None,
                 cognitive_capabilities: Optional[List[str]] = None):
        """Initialize the Agno adapter.
        
        Args:
            agent: An Agno agent instance
            agent_id: Unique identifier for the agent (generated if not provided)
            name: Name of the agent (taken from agent if available)
            metadata: Additional metadata about the agent
            cognitive_capabilities: List of cognitive capabilities
        """
        # Extract capabilities from the Agno agent's tools
        capabilities = []
        if hasattr(agent, 'tools') and agent.tools:
            for tool in agent.tools:
                if hasattr(tool, 'name'):
                    capabilities.append(tool.name)
        
        super().__init__(
            agent=agent,
            agent_id=agent_id,
            name=name or getattr(agent, 'name', 'Agno Agent'),
            framework="agno",
            capabilities=capabilities,
            metadata=metadata or {}
        )
        
        # Store session history for continuity
        self.sessions = {}
    
    def _initialize_session(self, session_id, request):
        """Helper to initialize session and set agent properties"""
        # Initialize session if it doesn't exist
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "history": [],
                "agent_state": {}
            }
        
        # Get or set the agent_id and session_id for the Agno agent
        if hasattr(self.agent, 'agent_id') and not self.agent.agent_id:
            self.agent.agent_id = str(self.agent_id)
        
        if hasattr(self.agent, 'session_id') and not self.agent.session_id:
            self.agent.session_id = str(session_id)
            
        # Set stream mode if applicable
        if hasattr(self.agent, 'stream'):
            self.agent.stream = request.stream
    
    def _extract_response(self, result):
        """Extract content and tool calls from Agno response"""
        tool_calls = []
        # Extract tool calls if they exist and are visible
        if result and hasattr(self.agent, 'show_tool_calls') and self.agent.show_tool_calls:
            if hasattr(result, 'tool_calls'):
                tool_calls = result.tool_calls
            elif hasattr(result, 'get_tool_calls'):
                tool_calls = result.get_tool_calls()
        
        # Extract the response content
        if result:
            if hasattr(result, 'response'):
                response_content = result.response
            elif hasattr(result, 'content'):
                response_content = result.content
            else:
                response_content = str(result)
        else:
            response_content = "No response generated."
            
        return response_content, tool_calls
    
    def _create_response(self, session_id, response_content, request, tool_calls=None):
        """Create response and update session history"""
        # Store the response in session history
        self.sessions[session_id]["history"].append({
            "role": MessageRole.AGENT,
            "content": response_content
        })
        
        # Create and return the response
        return ActionResponse(
            agent_id=self.agent_id,
            session_id=session_id,
            message=response_content,
            role=MessageRole.AGENT,
            metadata=request.metadata,
            tool_calls=tool_calls if tool_calls else None
        )

    def _download_content_from_url(self, url: str) -> bytes:
        """Download content from a URL.
        
        Args:
            url: URL to download content from
            
        Returns:
            Downloaded content as bytes
            
        Raises:
            Exception: If download fails
        """
        with httpx.Client() as client:
            response = client.get(url)
            if response.status_code != 200:
                raise Exception(f"HTTP status {response.status_code}")
            return response.content
    
    def _decode_base64(self, base64_content: str) -> bytes:
        """Decode base64 content to bytes.
        
        Args:
            base64_content: Base64 encoded content
            
        Returns:
            Decoded content as bytes
        """
        return base64.b64decode(base64_content)
    
    def _process_with_agent(self, 
                          session_id: str, 
                          message: str, 
                          request: Union[ListenRequest, ViewRequest], 
                          agent_kwargs: Dict[str, Any]) -> ActionResponse:
        """Process a request with the Agno agent.
        
        Args:
            session_id: Session ID
            message: Message to process
            request: The original request
            agent_kwargs: Arguments to pass to agent.run()
            
        Returns:
            Agent response
        """
        try:
            result = self.agent.run(message, **agent_kwargs)
            response_content, tool_calls = self._extract_response(result)
        except Exception as e:
            return self._create_response(
                session_id,
                f"Error processing with Agno: {str(e)}",
                request
            )
            
        return self._create_response(session_id, response_content, request, tool_calls)
    
    def act(self, request: ActionRequest) -> ActionResponse:
        """
        Acts in the environment and updates its internal cognitive state.
        
        Args:
            request: The action request to process
            
        Returns:
            ActionResponse: The response from the agent
        """
        session_id = request.session_id
        message = request.content
        
        # Initialize session and configure agent
        self._initialize_session(session_id, request)
        
        # Store the request message in session history
        self.sessions[session_id]["history"].append({
            "role": request.role,
            "content": message
        })
        
        # Process the request with the Agno agent
        try:
            result = self.agent.run(message)
            response_content, tool_calls = self._extract_response(result)
        except Exception as e:
            response_content = f"Error processing request: {str(e)}"
            tool_calls = []
        
        # Create and return the response
        return self._create_response(session_id, response_content, request, tool_calls)
    
    def listen(self, listen_request: ListenRequest) -> ActionResponse:
        """
        Process audio input and respond accordingly.
        
        Args:
            listen_request: The listen request containing both action request data and audio data
            
        Returns:
            ActionResponse: The response from the agent
        """
        session_id = listen_request.session_id
        message = listen_request.message or "Process this audio input"
        
        # Initialize session and configure agent
        self._initialize_session(session_id, listen_request)
        
        # Store the request in session history with audio reference
        self.sessions[session_id]["history"].append({
            "role": listen_request.role,
            "content": message,
            "has_audio": True
        })
        
        # Import Agno's Audio class
        from agno.media import Audio
        
        # Create Audio object based on input type
        try:
            if listen_request.audio.url:
                # Agno's Audio class supports direct URL handling
                agno_audio = Audio(url=listen_request.audio.url)
            elif listen_request.audio.base64_audio:
                audio_bytes = self._decode_base64(listen_request.audio.base64_audio)
                agno_audio = Audio(content=audio_bytes)
            else:
                return self._create_response(
                    session_id, 
                    "No audio data provided. Either URL or base64-encoded audio is required.", 
                    listen_request
                )
        except Exception as e:
            return self._create_response(
                session_id,
                f"Error preparing audio content: {str(e)}",
                listen_request
            )
        
        # Process with Agno
        return self._process_with_agent(
            session_id=session_id,
            message=message,
            request=listen_request,
            agent_kwargs={"audio": [agno_audio]}
        )

    def view(self, view_request: ViewRequest) -> ActionResponse:
        """
        Process image or video input and respond accordingly.
        
        Args:
            view_request: The view request containing both action request data and image/video data
            
        Returns:
            ActionResponse: The response from the agent
        """
        session_id = view_request.session_id
        message = view_request.message or "Process this visual input"
        
        # Initialize session and configure agent
        self._initialize_session(session_id, view_request)
        
        # Import Agno's media classes
        from agno.media import Image as AgnoImage, Video as AgnoVideo
        
        # Determine media type and store in session history with appropriate reference
        if isinstance(view_request.media, ImageArtifact):
            media_type = "image"
            self.sessions[session_id]["history"].append({
                "role": view_request.role,
                "content": message,
                "has_image": True
            })
            AgnoMediaClass = AgnoImage
            media_param_name = "images"
            
            # Get appropriate data access attributes based on media type
            url_attr = "url"
            base64_attr = "base64_image"
            
        elif isinstance(view_request.media, VideoArtifact):
            media_type = "video"
            self.sessions[session_id]["history"].append({
                "role": view_request.role,
                "content": message,
                "has_video": True
            })
            AgnoMediaClass = AgnoVideo
            media_param_name = "videos"
            
            # Get appropriate data access attributes based on media type
            url_attr = "url"
            base64_attr = "base64_video"
            
        else:
            return self._create_response(
                session_id, 
                "Unsupported media type provided. Must be an image or video.", 
                view_request
            )
        
        # Create Agno media object
        try:
            # Get URL and base64 values dynamically
            url = getattr(view_request.media, url_attr)
            base64_content = getattr(view_request.media, base64_attr)
            
            if url:
                # Download content from the URL first (Agno media classes need content, not URL)
                try:
                    content_bytes = self._download_content_from_url(url)
                except Exception as e:
                    return self._create_response(
                        session_id,
                        f"Error downloading {media_type} from URL: {str(e)}",
                        view_request
                    )
                
                # Create Agno media with the downloaded content
                agno_media = AgnoMediaClass(content=content_bytes)
                
            elif base64_content:
                # Handle base64 data
                try:
                    content_bytes = self._decode_base64(base64_content)
                except Exception as e:
                    return self._create_response(
                        session_id,
                        f"Error decoding base64 {media_type}: {str(e)}",
                        view_request
                    )
                
                agno_media = AgnoMediaClass(content=content_bytes)
                
            else:
                return self._create_response(
                    session_id,
                    f"No {media_type} data provided. Either URL or base64-encoded {media_type} is required.",
                    view_request
                )
                
        except Exception as e:
            return self._create_response(
                session_id,
                f"Error creating {media_type}: {str(e)}",
                view_request
            )
            
        # Process with Agno using the appropriate media parameter
        agent_kwargs = {media_param_name: [agno_media]}
        
        return self._process_with_agent(
            session_id=session_id,
            message=message,
            request=view_request,
            agent_kwargs=agent_kwargs
        )

"""
Cognitive adapter for Agno agents.

This module provides a cognitive adapter that extends the Agno agent framework
with cognitive capabilities inspired by TinyTroupe.
"""

from typing import Any, Dict, List, Optional
from uuid import UUID

from pebble.core.cognitive_protocol import CognitiveAgentProtocol
from pebble.schemas.cognitive_models import (
    StimulusType,
    CognitiveRequest,
    CognitiveResponse
)
from pebble.schemas.models import (
    ActionRequest, 
    ActionResponse, 
    MessageRole
)


class AgnoCognitiveAdapter(CognitiveAgentProtocol):
    """Cognitive adapter for Agno agents."""
    
    def __init__(self, agent, agent_id=None, name=None, metadata=None, cognitive_capabilities=None):
        """Initialize the Agno cognitive adapter.
        
        Args:
            agent: An Agno agent instance
            agent_id: Unique identifier for the agent (generated if not provided)
            name: Name of the agent (taken from agent if available)
            metadata: Additional metadata about the agent
            cognitive_capabilities: List of cognitive capabilities
        """
        # Extract capabilities from the Agno agent's tools
        capabilities = []
        if hasattr(agent, 'tools') and agent.tools:
            for tool in agent.tools:
                if hasattr(tool, 'name'):
                    capabilities.append(tool.name)
        
        # If cognitive capabilities are not specified, assume the agent can do everything
        if cognitive_capabilities is None:
            cognitive_capabilities = ["act", "listen", "see", "think"]
        
        super().__init__(
            agent=agent,
            agent_id=agent_id,
            name=name or getattr(agent, 'name', 'Agno Cognitive Agent'),
            framework="agno",
            capabilities=capabilities,
            metadata=metadata or {},
            cognitive_capabilities=cognitive_capabilities
        )
        
        # Store session history for continuity
        self.sessions = {}
    
    def process_action(self, request: ActionRequest) -> ActionResponse:
        """Process an action request with an Agno agent.
        
        Args:
            request: The action request to process
            
        Returns:
            ActionResponse: The response from the agent
        """
        session_id = request.session_id
        
        # Initialize session if it doesn't exist
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "history": [],
                "agent_state": {}
            }
        
        # Get or set the agent_id and session_id for the Agno agent
        if hasattr(self.agent, 'agent_id') and not self.agent.agent_id:
            self.agent.agent_id = str(self.agent_id)
        
        if hasattr(self.agent, 'session_id') and not self.agent.session_id:
            self.agent.session_id = str(session_id)
        
        # Create message for Agno agent
        message = request.message
        
        # Store the request message in session history
        self.sessions[session_id]["history"].append({
            "role": request.role,
            "content": message
        })
        
        # Set stream mode if applicable
        if hasattr(self.agent, 'stream'):
            self.agent.stream = request.stream
        
        # Process the request with the Agno agent
        tool_calls = []
        try:
            result = self.agent.run(message)
            
            # Extract tool calls if they exist and are visible
            if hasattr(self.agent, 'show_tool_calls') and self.agent.show_tool_calls:
                if hasattr(result, 'tool_calls'):
                    tool_calls = result.tool_calls
                elif hasattr(result, 'get_tool_calls'):
                    tool_calls = result.get_tool_calls()
            
            # Extract the response content
            if hasattr(result, 'response'):
                response_content = result.response
            elif hasattr(result, 'content'):
                response_content = result.content
            else:
                response_content = str(result)
            
        except Exception as e:
            logger.error(f"Error in cognitive operation: {e}")
            # Implement retry logic or fallback
            retry_count = request.metadata.get("retry_count", 0)
            if retry_count < MAX_RETRIES:
                # Modify request for retry with simplified prompt
                request.metadata["retry_count"] = retry_count + 1
                return self.act(request)  # Recursively retry
            else:
                # Return graceful failure response
                return CognitiveResponse(
                    agent_id=self.agent_id,
                    session_id=request.session_id,
                    content="I'm having trouble processing this request. Let's try a different approach.",
                    stimulus_type=request.stimulus_type,
                    cognitive_state=self.cognitive_state,
                    metadata={"error": str(e)}
                )
        
        # Store the response in session history
        self.sessions[session_id]["history"].append({
            "role": MessageRole.AGENT,
            "content": response_content
        })
        
        # Create and return the response
        return ActionResponse(
            agent_id=self.agent_id,
            session_id=session_id,
            message=response_content,
            role=MessageRole.AGENT,
            metadata=request.metadata,
            tool_calls=tool_calls if tool_calls else None
        )
    
    def _extract_cognitive_metadata(self, result: Any) -> Dict[str, Any]:
        """Extract cognitive metadata from the Agno agent's response.
        
        Args:
            result: The result from the Agno agent
            
        Returns:
            Dict[str, Any]: Cognitive metadata extracted from the result
        """
        cognitive_metadata = {}
        
        # Try to extract emotional state if available
        if hasattr(result, 'metadata') and result.metadata:
            if 'emotional_state' in result.metadata:
                cognitive_metadata['mental_state'] = {
                    'emotions': result.metadata['emotional_state']
                }
            
            # Try to extract other cognitive states
            if 'cognitive_state' in result.metadata:
                cognitive_metadata.update(result.metadata['cognitive_state'])
        
        return cognitive_metadata

        
