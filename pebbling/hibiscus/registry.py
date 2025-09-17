# 
# |---------------------------------------------------------|
# |                                                         |
# |                 Give Feedback / Get Help                |
# | https://github.com/Pebbling-ai/pebble/issues/new/choose |
# |                                                         |
# |---------------------------------------------------------|
#
#  Thank you users! We ❤️ you! - 🐧

"""Hibiscus DID registry integration for Pebbling servers."""

import json
from typing import Any, Dict

from pydantic.types import SecretStr

from pebbling.common.models import AgentManifest
from pebbling.utils.http_helper import make_api_request
from pebbling.utils.logging import get_logger

# Initialize logger for this module
logger = get_logger("pebbling.hibiscus")


class HibiscusClient:
    """Client for interacting with Hibiscus agent registry."""
    
    def __init__(
        self,
        pat_token: SecretStr,
        email: str,
        hibiscus_url: str = "http://localhost:19191",
    ):
        """Initialize Hibiscus client.
        
        Args:
            hibiscus_url: URL of Hibiscus registry
            pat_token: API key for authentication with Hibiscus registry
            email: Email address associated with the API key
        """
        self.hibiscus_url = hibiscus_url
        self.pat_token = pat_token
        self.email = email
        self.agents_endpoint = f"{self.hibiscus_url}/penguins"
        self.auth_challenge_endpoint = f"{self.hibiscus_url}/auth/api-challenge"
        self.auth_token_endpoint = f"{self.hibiscus_url}/auth/api-token"
        self.certificates_endpoint = f"{self.hibiscus_url}/certificates"
    
    async def request_api_challenge(self) -> Dict[str, Any]:
        """Request an authentication challenge using API key.
            
        Returns:
            Challenge response containing challenge string and expiration
        """
        payload = {
            "api_key": str(self.pat_token.get_secret_value()),
            "email": self.email
        }
        
        try:
            response = await make_api_request(
                url=self.auth_challenge_endpoint,
                method="POST",
                payload=payload
            )
            
            if response["success"]:
                return response["data"]
            else:
                error_msg = response.get("error", "Unknown error")
                logger.error(f"Failed to request API challenge: {error_msg}")
                raise Exception(f"Failed to request API challenge: {error_msg}")
        except Exception as e:
            logger.error(f"Error requesting API challenge: {str(e)}")
            raise
    
    async def get_api_token(self, challenge: str) -> str:
        """Get JWT access token using API key and challenge.
        
        Args:
            challenge: Challenge string from previous request
            
        Returns:
            JWT access token
        """
        payload = {
            "api_key": str(self.pat_token.get_secret_value()),
            "email": self.email,
            "challenge": challenge
        }
        
        try:
            response = await make_api_request(
                url=self.auth_token_endpoint,
                method="POST",
                payload=payload
            )
            
            if response["success"]:
                return response["data"]["access_token"]
            else:
                error_msg = response.get("error", "Unknown error")
                logger.error(f"Failed to get API token: {error_msg}")
                raise Exception(f"Failed to get API token: {error_msg}")
        except Exception as e:
            logger.error(f"Error getting API token: {str(e)}")
            raise
    
    async def authenticate(self) -> str:
        """Perform full authentication flow to get JWT token.
            
        Returns:
            JWT access token
        """
        try:
            # Step 1: Request challenge
            challenge_response = await self.request_api_challenge()
            challenge = challenge_response["challenge"]
            
            # Step 2: Get token using challenge
            access_token = await self.get_api_token(challenge)
            
            logger.info(f"Successfully authenticated for email: {self.email}")
            return access_token
        except Exception as e:
            logger.error(f"Authentication failed for email {self.email}: {str(e)}")
            raise
    
    async def register_agent(
        self,
        agent_manifest: AgentManifest,
        issue_certificate: bool = False,
        csr_data: str = None,
        certificate_validity_days: int = 365,
        **kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Register an agent with Hibiscus registry.
        
        Args:
            agent_manifest: Agent manifest with capabilities and skills
            issue_certificate: Whether to issue a certificate after registration (default False)
            csr_data: PEM-encoded Certificate Signing Request (required if issue_certificate=True)
            certificate_validity_days: Certificate validity period in days (default 365)
            **kwargs: Additional fields to include in the registration
            
        Returns:
            Response from Hibiscus registry, optionally including certificate data
        """
        # First authenticate to get JWT token
        access_token = await self.authenticate()
        try:
            # Create base penguin data
            payload = {
                "name": agent_manifest.name,
                "description": agent_manifest.description,
                "version": agent_manifest.version,
                "penguin_type": "ai_agent",
            }
            
            # Add optional base fields
            if hasattr(agent_manifest, "documentation_url") and agent_manifest.documentation_url:
                payload["documentation"] = agent_manifest.documentation_url
            
            # Process capabilities for AI agent
            capabilities = {}
            if agent_manifest and hasattr(agent_manifest, 'capabilities'):
                if hasattr(agent_manifest.capabilities, 'model_dump'):
                    try:
                        caps_dict = agent_manifest.capabilities.model_dump(exclude_none=True)
                        if "push_notifications" in caps_dict:
                            capabilities["push_notifications"] = bool(caps_dict["push_notifications"])
                        if "state_transition_history" in caps_dict:
                            capabilities["state_transition_history"] = bool(caps_dict["state_transition_history"])
                        if "streaming" in caps_dict:
                            capabilities["streaming"] = bool(caps_dict["streaming"])
                    except Exception as e:
                        logger.error(f"Error processing capabilities: {e}")
            
            # Process skills for AI agent 
            skills = {}
            if agent_manifest and hasattr(agent_manifest, 'skills') and agent_manifest.skills:
                try:
                    # AgentManifest.skills is a list, process all skills
                    processed_skills = []
                    for skill in agent_manifest.skills:
                        if hasattr(skill, 'model_dump'):
                            skill_dict = skill.model_dump(exclude_none=True)
                        else:
                            # Handle dict-like skill objects
                            skill_dict = dict(skill) if hasattr(skill, 'keys') else {}
                        
                        processed_skill = {
                            "id": str(skill_dict.get("id", skill_dict.get("name", "default"))).lower().replace(" ", "_"),
                            "name": skill_dict.get("name", ""),
                            "description": skill_dict.get("description", ""),
                            "tags": skill_dict.get("tags", ["general"]),
                            "examples": skill_dict.get("examples", [])
                        }
                        processed_skills.append(processed_skill)
                    
                    skills = {"skills": processed_skills}
                        
                except Exception as e:
                    logger.error(f"Error processing skills: {e}")
                    skills = {"skills": [{"id": "default", "name": "General Purpose", "description": "General purpose agent capability", "tags": ["general"], "examples": []}]}
            else:
                # Default skill if none provided
                skills = {"skills": [{"id": "default", "name": "General Purpose", "description": "General purpose agent capability", "tags": ["general"], "examples": []}]}
            
            # Create AI agent data structure
            ai_agent_data = {
                "did": agent_manifest.identity.get('did', '') if agent_manifest.identity else '',
                "did_document": agent_manifest.identity.get('did_document', {}) if agent_manifest.identity else {},
                "public_key": agent_manifest.identity.get('public_key', '') if agent_manifest.identity else '',
                "public_key_hash": "",  # This might need to be computed from public_key
                "capabilities": capabilities,
                "skills": skills
            }
            
            # Add API endpoint to ai_agent_data if available
            if hasattr(agent_manifest, "api_endpoint") and agent_manifest.api_endpoint:
                ai_agent_data["api_endpoint"] = str(agent_manifest.api_endpoint)
                
            # Add optional base penguin fields
            if hasattr(agent_manifest, "image_url") and agent_manifest.image_url:
                payload["image_url"] = str(agent_manifest.image_url)
                
            if hasattr(agent_manifest, "website_url") and agent_manifest.website_url:
                payload["website_url"] = str(agent_manifest.website_url)
                
            if hasattr(agent_manifest, "contact_email") and agent_manifest.contact_email:
                payload["contact_email"] = agent_manifest.contact_email
            
            # Extract public key from DID document if available and not already set
            if (agent_manifest and agent_manifest.identity and 
                agent_manifest.identity.get('did_document') and not ai_agent_data["public_key"]):
                
                # Extract public key from DID document verification methods
                for vm in ai_agent_data["did_document"].get("verificationMethod", []):
                    if "publicKeyPem" in vm:
                        ai_agent_data["public_key"] = vm.get("publicKeyPem", "")
                        break
            
            # Add ai_agent_data to payload
            payload["ai_agent_data"] = ai_agent_data
            
            # Update with any additional kwargs
            for key, value in kwargs.items():
                if key not in payload and value is not None:
                    payload[key] = value
            
            # Make the API call with JWT token
            headers = {"Authorization": f"Bearer {access_token}"}
            try:
                logger.debug(f"Sending registration to Hibiscus: {self.agents_endpoint}")
                response = await make_api_request(
                    url=self.agents_endpoint,
                    method="POST",
                    payload=payload,
                    headers=headers
                )
                
                if response["success"]:
                    logger.info(f"Successfully registered penguin (AI agent) with Hibiscus: {agent_manifest.name}")
                    result = response["data"]
                    
                    # Issue certificate if requested
                    if issue_certificate:
                        if not csr_data:
                            logger.error("Certificate issuance requested but no CSR data provided")
                            raise ValueError("CSR data is required when issue_certificate=True")
                        
                        try:
                            # Get the penguin ID from registration response
                            penguin_id = result.get("id")
                            if not penguin_id:
                                logger.error("No penguin ID returned from registration")
                                raise ValueError("Unable to issue certificate: no penguin ID from registration")
                            
                            # Issue certificate for the newly registered agent
                            certificate_result = await self.issue_certificate(
                                csr_data=csr_data,
                                penguin_id=penguin_id,
                                validity_days=certificate_validity_days
                            )
                            
                            # Add certificate data to the result
                            result["certificate"] = certificate_result
                            logger.info(f"Certificate issued successfully for agent: {agent_manifest.name}")
                            
                        except Exception as cert_error:
                            logger.error(f"Certificate issuance failed after successful registration: {cert_error}")
                            # Return registration result but indicate certificate failure
                            result["certificate_error"] = str(cert_error)
                    
                    return result
                else:
                    error_msg = response.get("error", "Unknown error")
                    if response.get("status_code") == 422:
                        logger.error(f"Validation error (422) from Hibiscus API: {error_msg}")
                        logger.debug("Payload that caused the error: " + json.dumps(payload, indent=2, default=str))
                    else:
                        logger.error(f"Failed to register penguin: {error_msg}")
                    raise Exception(f"Failed to register penguin: {error_msg}")
            except Exception as e:
                logger.error(f"Error during penguin registration: {str(e)}")
                raise
        
        except Exception as e:
            logger.error(f"Error registering penguin with Hibiscus: {e}")
            return {"success": False, "error": str(e)}
    
    async def issue_certificate(
        self,
        csr_data: str,
        penguin_id: str,
        validity_days: int = 365
    ) -> Dict[str, Any]:
        """Issue a certificate for a penguin agent using Certificate Signing Request.
        
        Args:
            csr_data: PEM-encoded Certificate Signing Request
            penguin_id: ID of the penguin requesting the certificate  
            validity_days: Certificate validity period in days (default 365)
            
        Returns:
            Certificate response with issued certificate details
            
        Raises:
            Exception: If certificate issuance fails
        """
        # First authenticate to get JWT token
        access_token = await self.authenticate()
        
        try:
            payload = {
                "csr": csr_data,
                "penguin_id": penguin_id,
                "validity_days": validity_days
            }
            
            headers = {"Authorization": f"Bearer {access_token}"}
            
            logger.debug(f"Requesting certificate issuance from: {self.certificates_endpoint}/issue")
            response = await make_api_request(
                url=f"{self.certificates_endpoint}/issue",
                method="POST",
                payload=payload,
                headers=headers
            )
            
            if response["success"]:
                logger.info(f"Successfully issued certificate for penguin: {penguin_id}")
                return response["data"]
            else:
                error_msg = response.get("error", "Unknown error")
                logger.error(f"Failed to issue certificate: {error_msg}")
                raise Exception(f"Failed to issue certificate: {error_msg}")
                
        except Exception as e:
            logger.error(f"Error during certificate issuance: {str(e)}")
            raise
    
    async def verify_certificate(
        self,
        certificate_data: str,
        penguin_id: str
    ) -> Dict[str, Any]:
        """Verify a certificate and get MLTS token if valid.
        
        Args:
            certificate_data: PEM-encoded certificate to verify
            penguin_id: ID of the penguin presenting the certificate
            
        Returns:
            Verification response with validity status and MLTS token
            
        Raises:
            Exception: If certificate verification fails
        """
        # First authenticate to get JWT token  
        access_token = await self.authenticate()
        
        try:
            payload = {
                "certificate": certificate_data,
                "penguin_id": penguin_id
            }
            
            headers = {"Authorization": f"Bearer {access_token}"}
            
            logger.debug(f"Verifying certificate with: {self.certificates_endpoint}/verify")
            response = await make_api_request(
                url=f"{self.certificates_endpoint}/verify",
                method="POST",
                payload=payload,
                headers=headers
            )
            
            if response["success"]:
                result = response["data"]
                if result.get("valid"):
                    logger.info(f"Certificate verified successfully for penguin: {penguin_id}")
                else:
                    logger.warning(f"Certificate verification failed for penguin {penguin_id}: {result.get('message')}")
                return result
            else:
                error_msg = response.get("error", "Unknown error")
                logger.error(f"Failed to verify certificate: {error_msg}")
                raise Exception(f"Failed to verify certificate: {error_msg}")
                
        except Exception as e:
            logger.error(f"Error during certificate verification: {str(e)}")
            raise
    
    async def get_ca_certificate(self) -> Dict[str, Any]:
        """Get the Certificate Authority's public certificate.
        
        Returns:
            CA certificate details including PEM-encoded certificate
            
        Raises:
            Exception: If CA certificate retrieval fails
        """
        try:
            logger.debug(f"Retrieving CA certificate from: {self.certificates_endpoint}/ca-certificate")
            response = await make_api_request(
                url=f"{self.certificates_endpoint}/ca-certificate",
                method="GET"
            )
            
            if response["success"]:
                logger.info("Successfully retrieved CA certificate")
                return response["data"]
            else:
                error_msg = response.get("error", "Unknown error")
                logger.error(f"Failed to get CA certificate: {error_msg}")
                raise Exception(f"Failed to get CA certificate: {error_msg}")
                
        except Exception as e:
            logger.error(f"Error retrieving CA certificate: {str(e)}")
            raise
    
    async def register_agent_with_certificate(
        self,
        agent_manifest: AgentManifest,
        csr_data: str,
        certificate_validity_days: int = 365,
        **kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Register an agent and automatically issue a certificate.
        
        This is a convenience method that combines agent registration and certificate issuance.
        
        Args:
            agent_manifest: Agent manifest with capabilities and skills
            csr_data: PEM-encoded Certificate Signing Request
            certificate_validity_days: Certificate validity period in days (default 365)
            **kwargs: Additional fields to include in the registration
            
        Returns:
            Response from Hibiscus registry including certificate data
            
        Raises:
            Exception: If registration or certificate issuance fails
        """
        return await self.register_agent(
            agent_manifest=agent_manifest,
            issue_certificate=True,
            csr_data=csr_data,
            certificate_validity_days=certificate_validity_days,
            **kwargs
        )
