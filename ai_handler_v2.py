#!/usr/bin/env python3

from typing import Dict, List, Optional, Any, Callable
from openai import OpenAI
import json
import os
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
from dotenv import load_dotenv
import asyncio

# Load environment variables
load_dotenv()

class ConversationState(Enum):
    """Enum for tracking conversation state"""
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    ERROR = "error"

@dataclass
class TokenUsage:
    """Track token usage"""
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    timestamp: datetime

class Message:
    """Message in a conversation"""
    def __init__(self, role: str, content: str):
        self.role = role
        self.content = content

    def to_dict(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}

class AIHandler:
    """Advanced AI request handler using OpenAI directly"""
    
    def __init__(self, 
                 model_name: str = "gpt-4", 
                 temperature: float = 0.2,
                 streaming_callback: Optional[Callable[[str], None]] = None):
        self.model_name = model_name
        self.temperature = temperature
        self.streaming_callback = streaming_callback
        self.token_usage: List[TokenUsage] = []
        self.conversation_state = ConversationState.IDLE
        self.messages: List[Message] = []
        
        # Get API key from environment
        self.api_key = os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        
        # Initialize OpenAI client with explicit API key
        self.client = OpenAI(api_key=self.api_key)
        
        # Initialize system prompts
        self.specialized_prompts = {
            "base": """You are an advanced Kali Linux expert AI assistant with deep knowledge of security tools and best practices.
            You help users by suggesting and executing appropriate security tools and commands.
            Always consider security implications and provide clear explanations for your recommendations.
            If a task involves potential risks, clearly communicate them to the user.""",
            "error_recovery": """Analyze the error and provide recovery suggestions.
            Consider common failure points and best practices for resolution.
            Provide step-by-step recovery instructions when possible.""",
            "security_audit": """Perform a security audit of the proposed actions.
            Check for potential vulnerabilities and security implications.
            Suggest security enhancements and best practices."""
        }
    
    async def get_response(self, message: str, system_prompt: Optional[str] = None) -> str:
        """Get a response from the AI model"""
        messages = []
        
        # Add system prompt
        if system_prompt:
            messages.append(Message("system", system_prompt))
        else:
            messages.append(Message("system", self.specialized_prompts["base"]))
        
        # Add conversation history
        messages.extend(self.messages)
        
        # Add user message
        messages.append(Message("user", message))
        
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                response_text = ""
                usage = None
                
                if self.streaming_callback:
                    # Stream response
                    stream = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[m.to_dict() for m in messages],
                        temperature=self.temperature,
                        stream=True
                    )
                    
                    response_content = []
                    for chunk in stream:
                        if chunk.choices[0].delta.content:
                            content = chunk.choices[0].delta.content
                            response_content.append(content)
                            if self.streaming_callback:
                                self.streaming_callback(content)
                    
                    response_text = "".join(response_content)
                    
                    # Get token usage for streaming response
                    completion = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[m.to_dict() for m in messages],
                        temperature=self.temperature
                    )
                    usage = completion.usage
                else:
                    # Get response without streaming
                    completion = self.client.chat.completions.create(
                        model=self.model_name,
                        messages=[m.to_dict() for m in messages],
                        temperature=self.temperature
                    )
                    response_text = completion.choices[0].message.content
                    usage = completion.usage
                
                # Track token usage if available
                if usage:
                    self.track_token_usage(
                        usage.prompt_tokens,
                        usage.completion_tokens
                    )
                
                # Store messages
                self.messages.append(Message("user", message))
                self.messages.append(Message("assistant", response_text))
                
                return response_text
                
            except Exception as e:
                error_msg = str(e)
                retry_count += 1
                
                # Handle specific API errors
                if "rate_limit_exceeded" in error_msg.lower():
                    wait_time = min(4 ** retry_count, 60)  # Exponential backoff, max 60 seconds
                    print(f"\nRate limit exceeded. Waiting {wait_time} seconds...")
                    await asyncio.sleep(wait_time)
                    continue
                    
                elif "invalid_api_key" in error_msg.lower():
                    raise Exception("Invalid API key. Please check your OpenAI API key configuration.")
                    
                elif "context_length_exceeded" in error_msg.lower():
                    # Try to reduce context by removing older messages
                    if len(self.messages) > 2:
                        self.messages = self.messages[-2:]
                        continue
                    else:
                        raise Exception("Message is too long, even with minimal context.")
                
                # If we've exhausted retries or it's a different error
                if retry_count == max_retries:
                    self.conversation_state = ConversationState.ERROR
                    raise Exception(f"Error after {max_retries} retries: {error_msg}")
                
                # Wait before retrying other errors
                wait_time = 2 ** retry_count
                print(f"\nError occurred. Retrying in {wait_time} seconds...")
                await asyncio.sleep(wait_time)
    
    async def handle_error(self, command: str, error: str, previous_steps: List[str]) -> str:
        """Handle command execution errors"""
        self.conversation_state = ConversationState.ERROR
        
        error_context = f"""Command: {command}
        Error Message: {error}
        Previous Steps: {', '.join(previous_steps)}
        
        Suggest recovery steps and alternative approaches."""
        
        return await self.get_response(error_context, self.specialized_prompts["error_recovery"])
    
    async def audit_security(self, tools: List[str], commands: List[str], target: str) -> str:
        """Perform security audit of proposed actions"""
        audit_context = f"""Tools: {', '.join(tools)}
        Commands: {', '.join(commands)}
        Target: {target}
        
        Provide a security assessment and recommendations."""
        
        return await self.get_response(audit_context, self.specialized_prompts["security_audit"])
    
    def track_token_usage(self, prompt_tokens: int, completion_tokens: int) -> None:
        """Track token usage"""
        usage = TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            timestamp=datetime.now()
        )
        self.token_usage.append(usage)
    
    def get_token_usage_stats(self) -> Dict[str, Any]:
        """Get token usage statistics"""
        if not self.token_usage:
            return {"error": "No token usage data available"}
        
        total_prompt_tokens = sum(usage.prompt_tokens for usage in self.token_usage)
        total_completion_tokens = sum(usage.completion_tokens for usage in self.token_usage)
        total_tokens = total_prompt_tokens + total_completion_tokens
        
        return {
            "total_tokens": total_tokens,
            "total_prompt_tokens": total_prompt_tokens,
            "total_completion_tokens": total_completion_tokens,
            "average_tokens_per_request": total_tokens / len(self.token_usage),
            "request_count": len(self.token_usage),
            "first_request": self.token_usage[0].timestamp,
            "last_request": self.token_usage[-1].timestamp
        }
    
    def save_conversation_state(self, file_path: str) -> None:
        """Save conversation state to file"""
        state = {
            "messages": [
                {"role": msg.role, "content": msg.content}
                for msg in self.messages
            ],
            "token_usage": [
                {
                    "prompt_tokens": usage.prompt_tokens,
                    "completion_tokens": usage.completion_tokens,
                    "total_tokens": usage.total_tokens,
                    "timestamp": usage.timestamp.isoformat()
                }
                for usage in self.token_usage
            ],
            "state": self.conversation_state.value,
            "model": self.model_name,
            "temperature": self.temperature
        }
        
        with open(file_path, 'w') as f:
            json.dump(state, f, indent=2)
    
    def load_conversation_state(self, file_path: str) -> None:
        """Load conversation state from file"""
        with open(file_path, 'r') as f:
            state = json.load(f)
        
        # Restore messages
        self.messages = [
            Message(msg["role"], msg["content"])
            for msg in state["messages"]
        ]
        
        # Restore token usage
        self.token_usage = [
            TokenUsage(
                prompt_tokens=usage["prompt_tokens"],
                completion_tokens=usage["completion_tokens"],
                total_tokens=usage["total_tokens"],
                timestamp=datetime.fromisoformat(usage["timestamp"])
            )
            for usage in state["token_usage"]
        ]
        
        # Restore state
        self.conversation_state = ConversationState(state["state"])
        
        # Restore model settings
        self.model_name = state["model"]
        self.temperature = state["temperature"]
    
    def clear_memory(self) -> None:
        """Clear conversation memory"""
        self.messages = []
        
    def get_conversation_history(self) -> List[Message]:
        """Get the current conversation history"""
        return self.messages 