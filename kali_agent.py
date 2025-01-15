#!/usr/bin/env python3

import os
import sys
import yaml
import logging
import subprocess
import asyncio
from typing import Optional, Dict, List, Tuple, Union
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.logging import RichHandler
from rich.table import Table
from rich.progress import Progress
from dotenv import load_dotenv
from pydantic import BaseModel
import re

from tool_discovery import KaliToolDiscovery
from workflow_manager import WorkflowManager, Workflow, WorkflowStep
from workflow_planner import WorkflowPlanner, WorkflowPlan
from ai_handler_v2 import AIHandler, ConversationState
from console_analyzer import ConsoleAnalyzer, AnalysisResult

# Initialize Rich console
console = Console()

class CommandResult(BaseModel):
    """Model for command execution results"""
    success: bool
    output: str
    error: Optional[str] = None
    command: str
    timestamp: datetime = datetime.now()

class KaliAgent:
    """Kali Linux AI Agent"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize the Kali Linux AI Agent"""
        # Load configuration
        self.config = self.load_config(config_path)
        
        # Set up logging
        self.logger = self.setup_logging()
        
        # Initialize components
        self.tool_discovery = KaliToolDiscovery(
            scan_on_startup=self.config['tool_discovery']['scan_on_startup'],
            catalog_file=self.config['tool_discovery']['catalog_file'],
            update_interval=self.config['tool_discovery']['update_interval'],
            additional_paths=self.config['tool_discovery']['additional_paths']
        )
        
        # Initialize workflow manager
        self.workflow_manager = WorkflowManager(
            workflow_dir=self.config['workflows']['directory'],
            auto_save=self.config['workflows']['auto_save'],
            max_steps=self.config['workflows']['max_steps']
        )
        
        # Initialize AI handler with streaming callback
        self.ai = AIHandler(
            model=self.config['ai']['model'],
            temperature=self.config['ai']['temperature'],
            max_tokens=self.config['ai']['max_tokens'],
            streaming_callback=self.token_callback
        )
        
        # Set up security settings
        self.command_timeout = self.config['security']['command_timeout']
        self.blocked_commands = self.config['security']['blocked_commands']
        self.blocked_patterns = self.config['security']['blocked_patterns']
        
        # Set initial mode
        self.autonomous_mode = self.config['agent']['autonomous_mode']
        self.planning_mode = False
    
        # Initialize history
        self.history = []
        
        # Initialize console analyzer
        self.console_analyzer = ConsoleAnalyzer()
        
        # Add context tracking
        self.current_objective = None
        self.context_history = []
        
        # Show startup message
        self.show_startup_message()
    
    def load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Validate configuration
            self.validate_config(config)
            
            return config
            
        except Exception as e:
            console.print(f"[red]Error loading configuration: {e}[/red]")
            sys.exit(1)
    
    def validate_config(self, config: Dict) -> None:
        """Validate configuration structure and values"""
        required_sections = [
            'agent', 'ai', 'security', 'tool_discovery', 'workflows'
        ]
        
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Missing required configuration section: {section}")
        
        # Validate agent settings
        if 'autonomous_mode' not in config['agent']:
            config['agent']['autonomous_mode'] = False
        
        # Validate AI settings
        ai_required = ['model', 'temperature', 'max_tokens']
        for key in ai_required:
            if key not in config['ai']:
                raise ValueError(f"Missing required AI setting: {key}")
        
        # Validate security settings
        if 'command_timeout' not in config['security']:
            config['security']['command_timeout'] = 30
        if 'blocked_commands' not in config['security']:
            config['security']['blocked_commands'] = []
        if 'blocked_patterns' not in config['security']:
            config['security']['blocked_patterns'] = []
        
        # Validate tool discovery settings
        tool_discovery_required = [
            'scan_on_startup', 'catalog_file',
            'update_interval', 'additional_paths'
        ]
        for key in tool_discovery_required:
            if key not in config['tool_discovery']:
                raise ValueError(f"Missing required tool discovery setting: {key}")
        
        # Validate workflow settings
        workflow_required = ['directory', 'auto_save', 'max_steps']
        for key in workflow_required:
            if key not in config['workflows']:
                raise ValueError(f"Missing required workflow setting: {key}")
    
    def setup_logging(self) -> logging.Logger:
        """Set up logging configuration"""
        logger = logging.getLogger('kali_agent')
        logger.setLevel(logging.INFO)
        
        # Create handlers
        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler('kali_agent.log')
        
        # Create formatters
        console_formatter = logging.Formatter(
            '%(levelname)s: %(message)s'
        )
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Set formatters
        console_handler.setFormatter(console_formatter)
        file_handler.setFormatter(file_formatter)
        
        # Add handlers
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        return logger
    
    def token_callback(self, token: str) -> None:
        """Callback for streaming tokens"""
        console.print(token, style="bright_yellow", end="")
    
    def show_startup_message(self) -> None:
        """Show startup message with agent status"""
        console.print("\n[bold cyan]Kali Linux AI Agent[/bold cyan]")
        console.print("[yellow]Version:[/yellow] 1.0.0")
        console.print(f"[yellow]Mode:[/yellow] {'Autonomous' if self.autonomous_mode else 'Interactive'}")
        console.print("\n[bold]Status:[/bold]")
        
        # Show AI status
        console.print(
            f"[cyan]AI Model:[/cyan] {self.config['ai']['model']} "
            f"(temp={self.config['ai']['temperature']})"
        )
        
        # Show tool discovery status
        tools_count = len(self.tool_discovery.available_tools)
        console.print(f"[cyan]Available Tools:[/cyan] {tools_count}")
        
        # Show workflow status
        workflows = self.workflow_manager.list_workflows()
        console.print(f"[cyan]Saved Workflows:[/cyan] {len(workflows)}")
        
        console.print("\n[green]Agent ready for commands![/green]")
        
        if not self.autonomous_mode:
            console.print(
                "\n[yellow]Hint:[/yellow] Type 'help' to see available commands "
                "or start with 'plan' to create a workflow"
            )
    
    def is_dangerous_command(self, command: str) -> bool:
        """Check if a command is in the dangerous commands list"""
        return any(dc in command for dc in self.config['security']['dangerous_commands'])
    
    def is_allowed_autonomous_command(self, command: str) -> bool:
        """Check if a command is allowed to run autonomously"""
        allowed_commands = self.config['security'].get('allowed_autonomous_commands', [])
        return any(ac in command.split()[0] for ac in allowed_commands)
    
    def validate_command(self, command: str, autonomous: bool = False) -> Tuple[bool, str]:
        """Validate a command for security concerns"""
        if self.is_dangerous_command(command):
            return False, "This command is marked as dangerous"
        if autonomous and not self.is_allowed_autonomous_command(command):
            return False, "This command is not allowed in autonomous mode"
        return True, "Command validated"
    
    async def get_command_suggestion(self, user_input: str) -> List[str]:
        """Get command suggestions from AI handler"""
        try:
            # Create command prompt
            prompt = f"""Based on the following request, suggest appropriate Kali Linux commands:
            
            Request: {user_input}
            
            Available Tools:
            {', '.join(self.tool_discovery.available_tools.keys())}
            
            Format each command on a new line.
            Include a brief comment explaining what each command does.
            Consider security implications and best practices."""
            
            # Get command suggestions
            response = await self.ai.get_response(prompt)
            
            # Parse commands (ignore comments)
            commands = []
            for line in response.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract command part if there's a comment
                    command = line.split('#')[0].strip()
                    commands.append(command)
            
            return commands
            
        except Exception as e:
            self.logger.error(f"Error getting command suggestions: {e}")
            return []
    
    async def process_commands(self, commands: List[str]) -> None:
        """Process a list of commands"""
        if not commands:
            console.print("[yellow]No commands to execute[/yellow]")
            return
            
        console.print("\n[bold]Suggested Commands:[/bold]")
        for i, cmd in enumerate(commands, 1):
            console.print(f"\n[cyan]{i}.[/cyan] {cmd}")
        
        if not self.autonomous_mode:
            choices = ["all", "select", "none"]
            choice = Prompt.ask(
                "\n[bold]How would you like to proceed?[/bold]",
                choices=choices,
                default="select"
            )
            
            if choice == "none":
                return
                
            elif choice == "select":
                selected = Prompt.ask(
                    "\nEnter command numbers to execute (comma-separated)",
                    default="1"
                )
                try:
                    indices = [int(i.strip()) - 1 for i in selected.split(",")]
                    commands = [commands[i] for i in indices if 0 <= i < len(commands)]
                except (ValueError, IndexError):
                    console.print("[red]Invalid selection[/red]")
                    return
        
        # Execute commands
        with Progress() as progress:
            task = progress.add_task("[cyan]Executing commands...", total=len(commands))
            
            for cmd in commands:
                console.print(f"\n[bold]Executing:[/bold] {cmd}")
                
                result = self.execute_command(cmd)
                
                if result.success:
                    console.print("[green]Command completed successfully[/green]")
                    if result.output:
                        console.print(result.output)
                else:
                    console.print(f"[red]Command failed:[/red] {result.error}")
                    
                    # Get recovery suggestions
                    error_prompt = f"""Command failed: {cmd}
                    Error: {result.error}
                    
                    Suggest recovery steps or alternative approaches."""
                    
                    recovery_suggestion = await self.ai.get_response(error_prompt)
                    console.print(f"\n[yellow]Recovery Suggestion:[/yellow]\n{recovery_suggestion}")
                    
                    if not self.autonomous_mode:
                        if not Confirm.ask("Continue with next command?"):
                            break
                    else:
                        break
                
                progress.update(task, advance=1)
    
    async def execute_command(self, command: str, tool: Optional[str] = None) -> CommandResult:
        """Execute a shell command and analyze its output"""
        try:
            # Check if command is allowed
            if not self.is_command_allowed(command):
                return CommandResult(
                    success=False,
                    error="Command not allowed for security reasons"
                )
            
            # Execute command
            process = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.command_timeout
            )
            
            # Analyze output
            output = process.stdout if process.returncode == 0 else process.stderr
            analysis = self.console_analyzer.analyze_output(
                output,
                tool=tool
            )
            
            # Extract relevant context
            if self.current_objective:
                relevant_context, key_points = self.console_analyzer.extract_needed_context(
                    output,
                    self.current_objective,
                    tool=tool
                )
            else:
                relevant_context = output
                key_points = []
            
            # Update context history
            self.context_history.append({
                'command': command,
                'tool': tool,
                'analysis': analysis,
                'relevant_context': relevant_context,
                'key_points': key_points,
                'timestamp': datetime.now()
            })
            
            # Create result
            result = CommandResult(
                success=analysis.success,
                output=relevant_context,
                error="\n".join(analysis.errors) if analysis.errors else None,
                command=command,
                timestamp=datetime.now()
            )
            
            # Handle errors if any
            if not result.success:
                await self._handle_command_failure(result, tool)
            
            return result
            
        except subprocess.TimeoutExpired:
            return CommandResult(
                success=False,
                error=f"Command timed out after {self.command_timeout} seconds"
            )
            
        except Exception as e:
            return CommandResult(
                success=False,
                error=str(e)
            )
    
    async def _handle_command_failure(self, result: CommandResult, tool: Optional[str] = None) -> None:
        """Handle command failures and attempt recovery"""
        if not result.error:
            return
            
        # Get fix suggestion
        fix = self.console_analyzer.suggest_fix(result.error, tool)
        
        # Create recovery prompt
        prompt = f"""Command failed: {result.command}
        Error: {result.error}
        Suggested fix: {fix}
        
        Current objective: {self.current_objective or 'No specific objective'}
        
        Please suggest a recovery plan that includes:
        1. Immediate fix for the current error
        2. Alternative approach if the fix doesn't work
        3. Impact on the overall objective
        
        Format your response as:
        FIX: <immediate fix command or action>
        ALTERNATIVE: <alternative approach>
        IMPACT: <impact description>"""
        
        # Get recovery plan
        recovery_response = await self.ai.get_response(prompt)
        
        # Parse recovery plan
        fix_cmd = None
        alternative = None
        impact = None
        
        for line in recovery_response.split('\n'):
            line = line.strip()
            if line.startswith('FIX:'):
                fix_cmd = line.split('FIX:')[1].strip()
            elif line.startswith('ALTERNATIVE:'):
                alternative = line.split('ALTERNATIVE:')[1].strip()
            elif line.startswith('IMPACT:'):
                impact = line.split('IMPACT:')[1].strip()
        
        # Display recovery plan
        console.print("\n[bold yellow]Recovery Plan:[/bold yellow]")
        console.print(f"[cyan]Suggested Fix:[/cyan] {fix}")
        if fix_cmd:
            console.print(f"[cyan]Fix Command:[/cyan] {fix_cmd}")
        if alternative:
            console.print(f"[cyan]Alternative Approach:[/cyan] {alternative}")
        if impact:
            console.print(f"[cyan]Impact:[/cyan] {impact}")
        
        # In interactive mode, ask user what to do
        if not self.autonomous_mode:
            choices = ["apply_fix", "try_alternative", "skip", "abort"]
            choice = Prompt.ask(
                "\n[bold]How would you like to proceed?[/bold]",
                choices=choices,
                default="apply_fix"
            )
            
            if choice == "apply_fix" and fix_cmd:
                await self.execute_command(fix_cmd, tool)
            elif choice == "try_alternative" and alternative:
                await self.execute_command(alternative, tool)
            elif choice == "abort":
                raise Exception("Workflow aborted by user")
        else:
            # In autonomous mode, try the fix automatically
            if fix_cmd:
                await self.execute_command(fix_cmd, tool)
    
    async def process_user_input(self, user_input: str) -> None:
        """Process user input with objective tracking"""
        # Update current objective
        self.current_objective = user_input
        
        if user_input.lower().startswith(("plan", "create workflow")):
            await self.plan_workflow(user_input)
        else:
            # Get command suggestion(s)
            suggested_commands = await self.get_command_suggestion(user_input)
            
            # Process commands
            await self.process_commands(suggested_commands)
    
    def get_context_summary(self) -> str:
        """Get a summary of the current context"""
        if not self.context_history:
            return "No context available"
        
        summary_parts = []
        
        # Add current objective
        if self.current_objective:
            summary_parts.append(f"Current Objective: {self.current_objective}")
        
        # Add recent key points
        recent_points = []
        for ctx in reversed(self.context_history[-5:]):  # Last 5 commands
            recent_points.extend(ctx['key_points'])
        
        if recent_points:
            summary_parts.append("Recent Key Points:")
            summary_parts.extend(f"- {point}" for point in recent_points)
        
        # Add recent errors
        recent_errors = []
        for ctx in reversed(self.context_history[-5:]):
            if ctx['analysis'].errors:
                recent_errors.extend(ctx['analysis'].errors)
        
        if recent_errors:
            summary_parts.append("Recent Errors:")
            summary_parts.extend(f"- {error}" for error in recent_errors)
        
        return "\n".join(summary_parts)
    
    def is_command_allowed(self, command: str) -> bool:
        """Check if a command is allowed based on security rules"""
        # Convert command to lowercase for case-insensitive matching
        cmd_lower = command.lower()
        
        # Check against blocked commands
        for blocked in self.blocked_commands:
            if blocked.lower() in cmd_lower:
                return False
        
        # Check against blocked patterns
        for pattern in self.blocked_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return False
        
        # Additional security checks can be added here
        
        return True
    
    def show_tools(self, category: Optional[str] = None) -> None:
        """Show available security tools"""
        if not self.tool_discovery.available_tools:
            console.print("[yellow]No tools found. Run a tool scan first.[/yellow]")
            return
        
        if category:
            # Show tools in specific category
            if category not in self.tool_discovery.base_categories:
                console.print(f"[red]Category '{category}' not found[/red]")
                console.print("\n[bold]Available Categories:[/bold]")
                for cat in self.tool_discovery.base_categories:
                    console.print(f"- {cat}")
                return
            
            tools = self.tool_discovery.get_tools_in_category(category)
            if not tools:
                console.print(f"[yellow]No tools found in category '{category}'[/yellow]")
                return
            
            console.print(f"\n[bold]Tools in {category}:[/bold]")
            for tool in tools:
                console.print(f"\n[cyan]{tool['name']}[/cyan]")
                if tool.get('description'):
                    console.print(f"Description: {tool['description']}")
                if tool.get('version'):
                    console.print(f"Version: {tool['version']}")
                
        else:
            # Show all tools by category
            console.print("\n[bold]Available Security Tools:[/bold]")
            
            for category, tools in self.tool_discovery.base_categories.items():
                if tools:
                    console.print(f"\n[bold cyan]{category}:[/bold cyan]")
                    for tool in tools:
                        console.print(f"- {tool['name']}")
                        if tool.get('description'):
                            console.print(f"  {tool['description']}")
    
    def show_workflows(self) -> None:
        """Show saved workflows"""
        workflows = self.workflow_manager.list_workflows()
        
        if not workflows:
            console.print("[yellow]No saved workflows found[/yellow]")
            return
        
        console.print("\n[bold]Saved Workflows:[/bold]")
        
        # Group workflows by category
        by_category = {}
        for workflow in workflows:
            category = workflow.category or "uncategorized"
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(workflow)
        
        for category, category_workflows in by_category.items():
            console.print(f"\n[bold cyan]{category}:[/bold cyan]")
            
            for workflow in category_workflows:
                console.print(f"\n[cyan]{workflow.name}[/cyan]")
                if workflow.description:
                    console.print(f"Description: {workflow.description}")
                console.print(f"Steps: {len(workflow.steps)}")
                if workflow.last_run:
                    console.print(
                        f"Last Run: {workflow.last_run.strftime('%Y-%m-%d %H:%M:%S')}"
                    )
    
    def toggle_mode(self) -> None:
        """Toggle between autonomous and interactive modes"""
        self.autonomous_mode = not self.autonomous_mode
        mode = "Autonomous" if self.autonomous_mode else "Interactive"
        console.print(f"[green]Switched to {mode} mode[/green]")
        
        if self.autonomous_mode:
            console.print(
                "\n[yellow]Warning:[/yellow] In autonomous mode, commands will "
                "execute automatically unless they are flagged as dangerous."
            )
        else:
            console.print(
                "\n[green]Note:[/green] In interactive mode, you will be "
                "prompted before executing any commands."
            )
    
    async def run_workflow(self, workflow_name: str) -> None:
        """Run a saved workflow by name"""
        try:
            workflow = self.workflow_manager.get_workflow(workflow_name)
            if not workflow:
                console.print(f"[red]Workflow '{workflow_name}' not found[/red]")
                return
            
            await self.execute_workflow(workflow)
            
        except Exception as e:
            self.logger.error(f"Error running workflow: {e}")
            console.print(f"[red]Error running workflow: {e}[/red]")
    
    async def main_loop(self) -> None:
        """Main interaction loop"""
        while True:
            try:
                # Get user input
                user_input = Prompt.ask("\n[bold green]>[/bold green]")
                
                # Process commands
                if user_input.lower() == "exit":
                    break
                    
                elif user_input.lower() == "help":
                    self.show_help()
                    
                elif user_input.lower() == "tools":
                    self.show_tools()
                    
                elif user_input.lower().startswith("tools "):
                    category = user_input.split("tools ")[1].strip()
                    self.show_tools(category)
                    
                elif user_input.lower() == "workflows":
                    self.show_workflows()
                    
                elif user_input.lower().startswith("run "):
                    workflow_name = user_input.split("run ")[1].strip()
                    await self.run_workflow(workflow_name)
                    
                elif user_input.lower() == "mode":
                    self.toggle_mode()
                    
                else:
                    # Process as regular input or workflow planning
                    await self.process_user_input(user_input)
                
            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'exit' to quit[/yellow]")
                
            except Exception as e:
                self.logger.error(f"Error in main loop: {e}")
                console.print(f"[red]Error: {e}[/red]")
    
    async def run(self) -> None:
        """Run the Kali Linux AI Agent"""
        try:
            # Show startup message
            self.show_startup_message()
            
            # Enter main loop
            await self.main_loop()
            
        except Exception as e:
            self.logger.error(f"Error running agent: {e}")
            console.print(f"[red]Error running agent: {e}[/red]")
            
        finally:
            # Cleanup
            console.print("\n[green]Shutting down Kali Linux AI Agent...[/green]")
            
            # Save any pending changes
            if self.tool_discovery.has_changes:
                self.tool_discovery.save_catalog()
            
            # Close any open resources
            await self.ai.close()
    
    async def execute_workflow(self, workflow: Workflow) -> None:
        """Execute a workflow with context awareness"""
        console.print(f"\n[bold]Executing Workflow:[/bold] {workflow.name}")
        console.print(f"[yellow]{workflow.description}[/yellow]\n")
        
        # Set workflow as current objective
        self.current_objective = f"Execute workflow: {workflow.name} - {workflow.description}"
        
        with Progress() as progress:
            task = progress.add_task(f"[cyan]Executing {workflow.name}...", total=len(workflow.steps))
            
            for i, step in enumerate(workflow.steps, 1):
                console.print(f"\n[bold]Step {i}:[/bold] {step.description}")
                console.print(f"[yellow]Command:[/yellow] {step.command}")
                
                # Extract tool name from command if possible
                tool = step.command.split()[0] if step.command else None
                
                if not self.autonomous_mode:
                    # Show context before execution
                    console.print("\n[bold]Current Context:[/bold]")
                    console.print(self.get_context_summary())
                    
                    if not Confirm.ask("Execute this step?"):
                        continue
                
                # Execute command with tool context
                result = await self.execute_command(step.command, tool=tool)
                
                if result.success:
                    console.print("[green]Step completed successfully[/green]")
                    if result.output:
                        console.print(result.output)
                    
                    # Update workflow with results
                    step.last_run = datetime.now()
                    step.last_result = result
                    
                else:
                    console.print(f"[red]Step failed:[/red] {result.error}")
                    
                    # Get recovery plan
                    recovery_prompt = f"""Step failed in workflow: {workflow.name}
                    Current step ({i}/{len(workflow.steps)}): {step.description}
                    Command: {step.command}
                    Error: {result.error}
                    
                    Context:
                    {self.get_context_summary()}
                    
                    Suggest recovery steps that consider:
                    1. The current workflow objective
                    2. Progress made so far
                    3. Impact on remaining steps
                    4. Alternative approaches to achieve the step's goal
                    
                    Format your response as:
                    RECOVERY: <immediate recovery steps>
                    ALTERNATIVE: <alternative approach>
                    CONTINUE: <yes/no> <reason>"""
                    
                    recovery_response = await self.ai.get_response(recovery_prompt)
                    
                    # Parse recovery response
                    recovery_steps = None
                    alternative = None
                    should_continue = True
                    reason = ""
                    
                    for line in recovery_response.split('\n'):
                        line = line.strip()
                        if line.startswith('RECOVERY:'):
                            recovery_steps = line.split('RECOVERY:')[1].strip()
                        elif line.startswith('ALTERNATIVE:'):
                            alternative = line.split('ALTERNATIVE:')[1].strip()
                        elif line.startswith('CONTINUE:'):
                            continue_parts = line.split('CONTINUE:')[1].strip().split(' ', 1)
                            should_continue = continue_parts[0].lower() == 'yes'
                            reason = continue_parts[1] if len(continue_parts) > 1 else ""
                    
                    # Display recovery plan
                    console.print("\n[bold yellow]Recovery Plan:[/bold yellow]")
                    if recovery_steps:
                        console.print(f"[cyan]Recovery Steps:[/cyan] {recovery_steps}")
                    if alternative:
                        console.print(f"[cyan]Alternative Approach:[/cyan] {alternative}")
                    console.print(
                        f"[cyan]Recommendation:[/cyan] "
                        f"{'Continue' if should_continue else 'Abort'} - {reason}"
                    )
                    
                    if not self.autonomous_mode:
                        choices = ["retry", "alternative", "skip", "abort"]
                        choice = Prompt.ask(
                            "\n[bold]How would you like to proceed?[/bold]",
                            choices=choices,
                            default="retry"
                        )
                        
                        if choice == "retry":
                            # Retry the same command
                            result = await self.execute_command(step.command, tool=tool)
                            if not result.success:
                                if not Confirm.ask("Step failed again. Continue workflow?"):
                                    break
                        elif choice == "alternative" and alternative:
                            # Try alternative approach
                            result = await self.execute_command(alternative, tool=tool)
                            if not result.success:
                                if not Confirm.ask("Alternative approach failed. Continue workflow?"):
                                    break
                        elif choice == "abort":
                            break
                    else:
                        # In autonomous mode, follow the AI's recommendation
                        if should_continue:
                            if recovery_steps:
                                result = await self.execute_command(recovery_steps, tool=tool)
                            elif alternative:
                                result = await self.execute_command(alternative, tool=tool)
                        else:
                            break
                
                progress.update(task, advance=1)
                
                # Add small delay between steps
                await asyncio.sleep(1)
        
        # Update workflow metadata
        workflow.last_run = datetime.now()
        self.workflow_manager.save_workflow(workflow)
        
        # Clear current objective
        self.current_objective = None
    
    async def plan_workflow(self, user_input: str) -> None:
        """Plan a new workflow using AI handler with context awareness"""
        try:
            # Set planning as current objective
            self.current_objective = f"Plan workflow: {user_input}"
            
            # Create workflow prompt with context
            prompt = f"""Create a detailed security testing workflow based on the following:
            
            Request: {user_input}
            
            Available Tools:
            {', '.join(self.tool_discovery.available_tools.keys())}
            
            Current Context:
            {self.get_context_summary()}
            
            Format your response as follows:
            WORKFLOW: <workflow_name>
            DESCRIPTION: <workflow_description>
            CATEGORY: <category>
            STEP: <tool>: <command> # <step_description>
            STEP: <tool>: <command> # <step_description>
            ...
            
            Consider:
            1. Security implications and best practices
            2. Dependencies between steps
            3. Error handling and recovery options
            4. Resource usage and performance impact"""
            
            # Get workflow from AI
            workflow_response = await self.ai.get_response(prompt)
            
            # Parse response and create plan
            plan = self.workflow_planner.apply_gpt_response(workflow_response)
            
            # Validate plan
            is_valid, errors = self.workflow_planner.validate_plan()
            
            # Display plan
            plan.display()
            
            if not is_valid:
                console.print("\n[red]Validation Errors:[/red]")
                for error in errors:
                    console.print(f"- {error}")
            
            # Enter planning mode
            self.planning_mode = True
            
            while True:
                choice = Prompt.ask(
                    "\n[bold]What would you like to do?[/bold]",
                    choices=["execute", "modify", "save", "cancel"],
                    default="modify"
                )
                
                if choice == "execute":
                    if is_valid:
                        workflow = plan.to_workflow()
                        self.workflow_manager.save_workflow(workflow)
                        await self.execute_workflow(workflow)
                        break
                    else:
                        console.print("[red]Cannot execute invalid workflow[/red]")
                
                elif choice == "modify":
                    context = console.input("\nProvide additional context or modifications: ")
                    
                    # Get updated workflow with context
                    modify_prompt = f"""Modify the workflow based on the following:
                    
                    Original Request: {user_input}
                    Feedback: {context}
                    
                    Current Context:
                    {self.get_context_summary()}
                    
                    Use the same format as before."""
                    
                    workflow_response = await self.ai.get_response(modify_prompt)
                    plan = self.workflow_planner.apply_gpt_response(workflow_response)
                    is_valid, errors = self.workflow_planner.validate_plan()
                    plan.display()
                    
                    if not is_valid:
                        console.print("\n[red]Validation Errors:[/red]")
                        for error in errors:
                            console.print(f"- {error}")
                
                elif choice == "save":
                    if is_valid:
                        workflow = plan.to_workflow()
                        self.workflow_manager.save_workflow(workflow)
                        console.print("[green]Workflow saved successfully[/green]")
                        break
                    else:
                        console.print("[red]Cannot save invalid workflow[/red]")
                
                else:  # cancel
                    break
            
            self.planning_mode = False
            
        except Exception as e:
            self.logger.error(f"Error planning workflow: {e}")
            console.print(f"[red]Error planning workflow: {e}[/red]")
        
        finally:
            # Clear planning objective
            self.current_objective = None

def main():
    """Main entry point"""
    try:
        # Initialize agent
        agent = KaliAgent()
        
        # Run agent
        asyncio.run(agent.run())
        
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main() 