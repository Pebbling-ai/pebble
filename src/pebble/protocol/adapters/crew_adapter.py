"""
Adapter for CrewAI Agent integration with Pebble protocol.
"""
from typing import Any, Dict, Optional

from crewai import Agent as CrewAgent

from ..protocol import Protocol, Message, MessageType, AgentType


class CrewAdapter:
    """
    Adapter for CrewAI Agent integration with the Pebble protocol.
    
    This adapter provides the translation layer between CrewAI Agent's
    API and the standardized Pebble communication protocol.
    """
    
    def __init__(self, agent: CrewAgent):
        """
        Initialize the adapter with a CrewAI Agent instance.
        
        Args:
            agent: The CrewAgent instance to adapt
        """
        self.agent = agent
        self.protocol = Protocol()
    
    @property
    def agent_id(self) -> str:
        """Get the agent's unique identifier."""
        return getattr(self.agent, 'id', None) or str(id(self.agent))
    
    @property
    def agent_type(self) -> str:
        """Get the agent's type."""
        return AgentType.CREW
    
    async def send_message(self, message: Message) -> Optional[Message]:
        """
        Send a message to the CrewAI Agent and get its response.
        
        Args:
            message: Protocol message to send
            
        Returns:
            Optional[Message]: Response message if any
        """
        # Adapt the message for CrewAI Agent format
        adapted_message = Protocol.adapt_for_agent_type(message, self.agent_type)
        
        # Process based on message type
        if message.type == MessageType.TEXT:
            # For text messages, use the execute method
            response_content = await self.agent.execute(message.content)
            
            # Create response message
            return self.create_response(message, response_content)
            
        elif message.type == MessageType.COMMAND:
            # Handle command messages based on command content
            command = message.content.get("command") if isinstance(message.content, dict) else None
            args = message.content.get("args", {}) if isinstance(message.content, dict) else {}
            
            if command == "perform_task":
                try:
                    # Assuming CrewAgent has a method to perform tasks
                    result = await self.agent.execute_task(args.get("task", ""), **args.get("context", {}))
                    return self.create_response(message, {"result": result, "status": "success"})
                except Exception as e:
                    return self.create_response(
                        message, 
                        {"error": str(e), "status": "error"},
                        {"error_type": type(e).__name__}
                    )
                    
        # Default: no response for unsupported message types
        return None
    
    async def receive_message(self, message: Message) -> None:
        """
        Process a message received from another agent.
        
        Args:
            message: Protocol message received
        """
        print(f"CrewAgent {getattr(self.agent, 'name', 'Agent')} received message: {message.id}")
    
    def create_response(self, 
                        to_message: Message, 
                        content: Any, 
                        metadata: Optional[Dict[str, Any]] = None) -> Message:
        """
        Create a response message to another message.
        
        Args:
            to_message: The message being responded to
            content: Response content
            metadata: Additional metadata (optional)
            
        Returns:
            Message: The response message
        """
        meta = {"in_response_to": to_message.id}
        if metadata:
            meta.update(metadata)
            
        return Protocol.create_message(
            message_type=MessageType.RESPONSE,
            sender=self.agent_id,
            receiver=to_message.sender,
            content=content,
            metadata=meta
        )
