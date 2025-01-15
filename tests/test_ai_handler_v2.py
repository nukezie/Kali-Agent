#!/usr/bin/env python3

import asyncio
import os
from datetime import datetime
from rich.console import Console
from ai_handler_v2 import AIHandler
from dotenv import load_dotenv

console = Console()

# Load and verify API key
load_dotenv(override=True)
api_key = os.getenv('OPENAI_API_KEY')
if not api_key:
    console.print("[red]Error: OPENAI_API_KEY not found in environment variables[/red]")
    exit(1)

# Debug output
console.print("[yellow]Environment variables loaded from .env[/yellow]")
console.print(f"[yellow]Current working directory: {os.getcwd()}[/yellow]")
console.print(f"[yellow].env file exists: {os.path.exists('.env')}[/yellow]")
console.print(f"[green]API Key loaded: {api_key[:8]}...{api_key[-4:]}[/green]")

async def test_basic_interaction(ai: AIHandler):
    """Test basic interaction with the AI"""
    console.print("\n[bold cyan]Testing Basic Interaction[/bold cyan]")
    try:
        response = await ai.get_response("What security tools are commonly used for network scanning?")
        console.print(f"Response: {response}")
        return True
    except Exception as e:
        console.print(f"[red]Error in basic interaction: {str(e)}[/red]")
        return False

async def test_error_handling(ai: AIHandler):
    """Test error handling and recovery"""
    console.print("\n[bold cyan]Testing Error Handling[/bold cyan]")
    try:
        error_response = await ai.handle_error(
            command="nmap -sS -p- 192.168.1.1",
            error="Permission denied: You need to be root to run this scan",
            previous_steps=["whoami", "ifconfig"]
        )
        console.print(f"Error Recovery Suggestion: {error_response}")
        return True
    except Exception as e:
        console.print(f"[red]Error in error handling: {str(e)}[/red]")
        return False

async def test_security_audit(ai: AIHandler):
    """Test security auditing"""
    console.print("\n[bold cyan]Testing Security Audit[/bold cyan]")
    try:
        audit_result = await ai.audit_security(
            tools=["nmap", "metasploit", "wireshark"],
            commands=["nmap -sV -p 1-1000 192.168.1.0/24", "msfconsole -q"],
            target="192.168.1.0/24"
        )
        console.print(f"Security Audit Result: {audit_result}")
        return True
    except Exception as e:
        console.print(f"[red]Error in security audit: {str(e)}[/red]")
        return False

async def test_conversation_state(ai: AIHandler):
    """Test conversation state management"""
    console.print("\n[bold cyan]Testing Conversation State Management[/bold cyan]")
    try:
        # Add some conversation context
        await ai.get_response("I need to perform a network vulnerability scan.")
        await ai.get_response("What tools should I use for web application testing?")
        
        # Save state
        ai.save_conversation_state("conversation_state.json")
        console.print("Conversation state saved")
        
        # Create new AI instance and load state
        new_ai = AIHandler()
        new_ai.load_conversation_state("conversation_state.json")
        console.print("Conversation state loaded in new instance")
        
        # Verify state loaded correctly
        history = new_ai.get_conversation_history()
        console.print(f"Loaded {len(history)} messages from state")
        return True
    except Exception as e:
        console.print(f"[red]Error in conversation state: {str(e)}[/red]")
        return False

async def test_token_tracking(ai: AIHandler):
    """Test token usage tracking"""
    console.print("\n[bold cyan]Testing Token Usage Tracking[/bold cyan]")
    try:
        # Get real token usage from an API call
        await ai.get_response("Tell me about Kali Linux.")
        
        # Get usage stats
        stats = ai.get_token_usage_stats()
        console.print("Token Usage Stats:")
        for key, value in stats.items():
            console.print(f"{key}: {value}")
        return True
    except Exception as e:
        console.print(f"[red]Error in token tracking: {str(e)}[/red]")
        return False

async def main():
    """Main test function"""
    console.print("[bold green]Starting AI Handler V2 Tests[/bold green]")
    
    # Initialize AI Handler with custom streaming callback
    def custom_stream_callback(token: str):
        console.print(token, end="", style="bright_yellow")
    
    console.print("\n[bold cyan]Initializing AI Handler...[/bold cyan]")
    ai = AIHandler(streaming_callback=custom_stream_callback)
    
    try:
        # Run tests and collect results
        test_results = {}
        test_errors = {}
        
        # Define tests with descriptions
        tests = {
            "Basic Interaction": {
                "func": test_basic_interaction,
                "desc": "Testing basic Q&A functionality"
            },
            "Error Handling": {
                "func": test_error_handling,
                "desc": "Testing error recovery system"
            },
            "Security Audit": {
                "func": test_security_audit,
                "desc": "Testing security assessment"
            },
            "Conversation State": {
                "func": test_conversation_state,
                "desc": "Testing state persistence"
            },
            "Token Tracking": {
                "func": test_token_tracking,
                "desc": "Testing usage monitoring"
            }
        }
        
        # Run each test
        for test_name, test_info in tests.items():
            console.print(f"\n[bold cyan]{test_info['desc']}[/bold cyan]")
            try:
                test_results[test_name] = await test_info['func'](ai)
            except Exception as e:
                test_results[test_name] = False
                test_errors[test_name] = str(e)
        
        # Display test summary
        console.print("\n[bold white on blue]Test Summary[/bold white on blue]")
        
        passed_tests = 0
        total_tests = len(tests)
        
        for test_name, passed in test_results.items():
            status = "[green]✓ PASSED[/green]" if passed else "[red]✗ FAILED[/red]"
            console.print(f"[cyan]{test_name:.<30}[/cyan] {status}")
            
            # Show error if test failed
            if not passed and test_name in test_errors:
                console.print(f"  [red]Error: {test_errors[test_name]}[/red]")
            
            if passed:
                passed_tests += 1
        
        # Show overall progress
        progress = (passed_tests / total_tests) * 100
        console.print(f"\n[bold]Overall Progress: {progress:.1f}%[/bold]")
        
        # Check if all tests passed
        if all(test_results.values()):
            console.print("\n[bold green on black]All tests completed successfully![/bold green on black]")
        else:
            console.print(f"\n[bold yellow on black]{passed_tests}/{total_tests} tests passed. Check the summary above.[/bold yellow on black]")
            
    except Exception as e:
        console.print(f"\n[bold red]Error during testing: {str(e)}[/bold red]")
    finally:
        # Cleanup
        if os.path.exists("conversation_state.json"):
            os.remove("conversation_state.json")

if __name__ == "__main__":
    asyncio.run(main()) 