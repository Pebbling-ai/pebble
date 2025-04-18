"""
Agno-specific adapter for the Pebble protocol.
"""
from typing import Any, Dict, Optional
import uuid

from agno.agent import Agent as AgnoAgent

from pebble.agent.base_adapter import BaseProtocolHandler
from pebble.core.protocol import PebbleProtocol


class AgnoProtocolHandler(BaseProtocolHandler):
    """Protocol handler implementation for Agno agents."""
    
    def __init__(self, agent: AgnoAgent, agent_id: Optional[str] = None):
        """Initialize with an Agno agent."""
        super().__init__(agent_id)
        self.agent = agent
        
        # Initialize agent context if needed
        if not hasattr(self.agent, "context") or self.agent.context is None:
            self.agent.context = {}
        self.protocol = PebbleProtocol()
        
        # Initialize user-specific contexts
        self.user_contexts = {}
    
    def apply_user_context(self, user_id: str) -> None:
        """
        Apply user-specific context to the agent.
        
        Args:
            user_id: ID of the user to apply context for
        """
        # Store original context to restore after request
        self._original_context = self.agent.context.copy() if hasattr(self.agent, "context") else {}
        
        # Apply user-specific context if it exists
        if user_id in self.user_contexts:
            # Update agent context with user-specific context
            for key, context_item in self.user_contexts[user_id].items():
                self.agent.context[key] = context_item["value"]
                
            print(f"Applied context for user {user_id}: {self.user_contexts[user_id]}")
        else:
            print(f"No specific context found for user {user_id}")
            
    def reset_context(self) -> None:
        """Reset to original context after processing a user request."""
        if hasattr(self, "_original_context"):
            self.agent.context = self._original_context
            delattr(self, "_original_context")
            
    async def handle_Context(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle Context protocol (add/update/delete operations)."""
        request_id = params.get("id", str(uuid.uuid4()))
        operation = params.get("operation", "").lower()
        key = params.get("key")
        user_id = params.get("user_id")  # Optional user ID for user-specific context

        # Validate required parameters
        if not key:
            return self.protocol.create_error(
                request_id=request_id, code=400, 
                message="Key is required for Context operations"
            )

        if operation not in ["add", "update", "delete"]:
            return self.protocol.create_error(
                request_id=request_id, code=400,
                message=f"Invalid operation '{operation}'. Must be one of: add, update, delete"
            )

        # If user_id is provided, manage user-specific context
        if user_id:
            if user_id not in self.user_contexts:
                self.user_contexts[user_id] = {}
            
            # Redirect to user-specific context operations
            if operation == "add":
                return self._handle_add(request_id, key, params, user_id)
            elif operation == "update":
                return self._handle_update(request_id, key, params, user_id)
            else:  # delete
                return self._handle_delete(request_id, key, user_id)
        else:
            # Handle global context operations (original behavior)
            if operation == "add":
                return self._handle_add(request_id, key, params)
            elif operation == "update":
                return self._handle_update(request_id, key, params)
            else:  # delete
                return self._handle_delete(request_id, key)
            
    def _handle_add(self, request_id: str, key: str, params: Dict[str, Any], user_id: Optional[str] = None) -> Dict[str, Any]:
        """Handle add operation."""
        value = params.get("value")
        if not value:
            return self.protocol.create_error(
                request_id=request_id, code=400,
                message="Value is required for add operation"
            )

        # Store context with optional metadata
        context_data = {
            "value": value,
            "metadata": params.get("metadata", {})
        }
        
        if user_id:
            # Store in user-specific context
            self.user_contexts[user_id][key] = context_data
            message = f"Context added for user {user_id} successfully"
        else:
            # Store in global context
            self.agent.context[key] = context_data
            
            # Inject context into Agno agent if possible
            if hasattr(self.agent, "context") and isinstance(self.agent.context, dict):
                self.agent.context[key] = value
            
            message = "Context added successfully"
        
        return self.protocol.create_response(
            request_id=request_id,
            result={"key": key, "status": "success", "message": message}
        )

    def _handle_update(self, request_id: str, key: str, params: Dict[str, Any], user_id: Optional[str] = None) -> Dict[str, Any]:
        """Handle update operation."""
        context_store = self.user_contexts.get(user_id, {}) if user_id else self.agent.context
        
        if key not in context_store:
            return self.protocol.create_error(
                request_id=request_id, code=404,
                message=f"Context with key '{key}' not found" + (f" for user {user_id}" if user_id else "")
            )
            
        value = params.get("value")
        if value is None:
            return self.protocol.create_error(
                request_id=request_id, code=400,
                message="Value is required for Context update operation"
            )
            
        # Update context
        context_store[key]["value"] = value
        if "metadata" in params:
            context_store[key]["metadata"] = params["metadata"]
            
        # If global context, update in Agno agent if possible
        if not user_id and hasattr(self.agent, "context") and isinstance(self.agent.context, dict):
            self.agent.context[key] = value
            
        message = "Context updated successfully" + (f" for user {user_id}" if user_id else "")
        return self.protocol.create_response(
            request_id=request_id,
            result={"key": key, "status": "success", "message": message}
        )
        
    def _handle_delete(self, request_id: str, key: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Handle delete operation."""
        context_store = self.user_contexts.get(user_id, {}) if user_id else self.agent.context
        
        if key not in context_store:
            return self.protocol.create_error(
                request_id=request_id, code=404,
                message=f"Context with key '{key}' not found" + (f" for user {user_id}" if user_id else "")
            )
            
        # Delete context
        del context_store[key]
        
        # If global context, remove from Agno agent if possible
        if not user_id and hasattr(self.agent, "context") and isinstance(self.agent.context, dict) and key in self.agent.context:
            del self.agent.context[key]
        
        message = "Context deleted successfully" + (f" for user {user_id}" if user_id else "")
        return self.protocol.create_response(
            request_id=request_id,
            result={"key": key, "status": "success", "message": message}
        )