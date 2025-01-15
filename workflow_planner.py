#!/usr/bin/env python3

from typing import Dict, List, Optional, Tuple
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from workflow_manager import Workflow, WorkflowStep

console = Console()

class WorkflowPlan:
    def __init__(self, name: str, description: str, category: str):
        self.name = name
        self.description = description
        self.category = category
        self.steps: List[Dict] = []
        self.context: List[str] = []
        self.variables: Dict[str, str] = {}
        self.created_at = datetime.now()
        self.last_updated = datetime.now()
    
    def add_context(self, context: str) -> None:
        """Add user context to the workflow plan"""
        self.context.append(context)
        self.last_updated = datetime.now()
    
    def update_variables(self, variables: Dict[str, str]) -> None:
        """Update workflow variables"""
        self.variables.update(variables)
        self.last_updated = datetime.now()
    
    def set_steps(self, steps: List[Dict]) -> None:
        """Set workflow steps"""
        self.steps = steps
        self.last_updated = datetime.now()
    
    def to_workflow(self) -> Workflow:
        """Convert plan to actual workflow"""
        workflow = Workflow(self.name, self.description, self.category)
        for step in self.steps:
            workflow_step = WorkflowStep(
                step["tool"],
                step["command"].format(**self.variables),
                step["description"],
                step.get("requires", [])
            )
            workflow.add_step(workflow_step)
        return workflow
    
    def display(self) -> None:
        """Display the workflow plan"""
        # Display basic information
        console.print(Panel(
            f"[bold cyan]{self.name}[/bold cyan]\n"
            f"[yellow]{self.description}[/yellow]\n"
            f"Category: {self.category}\n"
            f"Last Updated: {self.last_updated.strftime('%Y-%m-%d %H:%M:%S')}",
            title="Workflow Plan"
        ))
        
        # Display context history
        if self.context:
            console.print("\n[bold]Context History:[/bold]")
            for i, ctx in enumerate(self.context, 1):
                console.print(f"{i}. {ctx}")
        
        # Display variables
        if self.variables:
            console.print("\n[bold]Variables:[/bold]")
            for key, value in self.variables.items():
                console.print(f"- {key}: {value}")
        
        # Display steps
        if self.steps:
            table = Table(title="\nWorkflow Steps")
            table.add_column("Step", style="cyan")
            table.add_column("Tool", style="green")
            table.add_column("Command", style="yellow")
            table.add_column("Description", style="magenta")
            
            for i, step in enumerate(self.steps, 1):
                table.add_row(
                    str(i),
                    step["tool"],
                    step["command"],
                    step["description"]
                )
            
            console.print(table)

class WorkflowPlanner:
    """Plans and updates workflows based on user context and available tools"""
    
    def __init__(self, available_tools: Dict[str, Dict]):
        self.available_tools = available_tools
        self.current_plan: Optional[WorkflowPlan] = None
    
    def create_plan_prompt(self, user_input: str, context: List[str] = None) -> str:
        """Create a prompt for GPT-4 to generate a workflow plan"""
        tools_by_category = {}
        for tool, info in self.available_tools.items():
            category = info['category']
            if category not in tools_by_category:
                tools_by_category[category] = []
            tools_by_category[category].append({
                "name": tool,
                "help": info.get("help", "")
            })
        
        prompt = "Create a detailed workflow plan based on the following information:\n\n"
        prompt += "USER REQUEST: " + user_input + "\n\n"
        
        if context:
            prompt += "PREVIOUS CONTEXT:\n"
            for ctx in context:
                prompt += f"- {ctx}\n"
            prompt += "\n"
        
        prompt += "AVAILABLE TOOLS BY CATEGORY:\n"
        for category, tools in tools_by_category.items():
            prompt += f"\n{category.upper()}:\n"
            for tool in tools:
                prompt += f"- {tool['name']}"
                if tool['help']:
                    prompt += f" ({tool['help'].split('\n')[0]})"
                prompt += "\n"
        
        prompt += "\nCreate a workflow plan using this format:\n"
        prompt += """
WORKFLOW: <workflow_name>
DESCRIPTION: <workflow_description>
CATEGORY: <category>
VARIABLES:
- <variable_name>: <description>
...
STEPS:
1. TOOL: <tool_name>
   COMMAND: <command_template>
   DESCRIPTION: <step_description>
   REQUIRES: [<required_tools>]
...
"""
        return prompt
    
    def parse_gpt_response(self, response: str) -> Tuple[str, str, str, Dict[str, str], List[Dict]]:
        """Parse GPT-4 response into workflow components"""
        lines = response.strip().split('\n')
        name = ""
        description = ""
        category = ""
        variables = {}
        steps = []
        
        current_section = None
        current_step = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if line.startswith("WORKFLOW:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("DESCRIPTION:"):
                description = line.split(":", 1)[1].strip()
            elif line.startswith("CATEGORY:"):
                category = line.split(":", 1)[1].strip()
            elif line.startswith("VARIABLES:"):
                current_section = "variables"
            elif line.startswith("STEPS:"):
                current_section = "steps"
            elif current_section == "variables" and line.startswith("-"):
                var_parts = line[1:].split(":", 1)
                if len(var_parts) == 2:
                    variables[var_parts[0].strip()] = var_parts[1].strip()
            elif current_section == "steps":
                if line.startswith("TOOL:"):
                    if current_step:
                        steps.append(current_step)
                    current_step = {"tool": line.split(":", 1)[1].strip()}
                elif line.startswith("COMMAND:") and current_step:
                    current_step["command"] = line.split(":", 1)[1].strip()
                elif line.startswith("DESCRIPTION:") and current_step:
                    current_step["description"] = line.split(":", 1)[1].strip()
                elif line.startswith("REQUIRES:") and current_step:
                    requires = line.split(":", 1)[1].strip()
                    current_step["requires"] = [r.strip() for r in requires.strip("[]").split(",")]
        
        if current_step:
            steps.append(current_step)
        
        return name, description, category, variables, steps
    
    def create_initial_plan(self, user_input: str) -> WorkflowPlan:
        """Create initial workflow plan from user input"""
        self.current_plan = None
        prompt = self.create_plan_prompt(user_input)
        # Note: This method needs to be implemented in the main agent class
        # as it requires access to the OpenAI client
        return prompt
    
    def update_plan(self, additional_context: str) -> str:
        """Update existing workflow plan with new context"""
        if not self.current_plan:
            raise ValueError("No current workflow plan exists")
        
        self.current_plan.add_context(additional_context)
        prompt = self.create_plan_prompt(
            additional_context,
            self.current_plan.context
        )
        return prompt
    
    def apply_gpt_response(self, response: str) -> WorkflowPlan:
        """Apply GPT-4 response to create or update workflow plan"""
        name, description, category, variables, steps = self.parse_gpt_response(response)
        
        if not self.current_plan:
            self.current_plan = WorkflowPlan(name, description, category)
        
        self.current_plan.update_variables(variables)
        self.current_plan.set_steps(steps)
        
        return self.current_plan
    
    def validate_plan(self) -> Tuple[bool, List[str]]:
        """Validate current workflow plan"""
        if not self.current_plan:
            return False, ["No workflow plan exists"]
        
        errors = []
        
        # Check if all tools are available
        for step in self.current_plan.steps:
            tool = step["tool"]
            if tool not in self.available_tools:
                errors.append(f"Tool '{tool}' is not available")
            
            # Check required tools
            for req in step.get("requires", []):
                if req not in self.available_tools:
                    errors.append(f"Required tool '{req}' is not available")
        
        # Check if all variables are defined
        for step in self.current_plan.steps:
            command = step["command"]
            try:
                # Try formatting the command with current variables
                command.format(**self.current_plan.variables)
            except KeyError as e:
                errors.append(f"Missing variable {e} in step: {command}")
        
        return len(errors) == 0, errors 