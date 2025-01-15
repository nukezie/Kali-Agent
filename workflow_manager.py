#!/usr/bin/env python3

import json
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime

class WorkflowStep:
    def __init__(self, tool: str, command: str, description: str, requires: List[str] = None):
        self.tool = tool
        self.command = command
        self.description = description
        self.requires = requires or []

class Workflow:
    def __init__(self, name: str, description: str, category: str):
        self.name = name
        self.description = description
        self.category = category
        self.steps: List[WorkflowStep] = []
        self.created_at = datetime.now()
        self.last_run = None
    
    def add_step(self, step: WorkflowStep):
        self.steps.append(step)
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "steps": [
                {
                    "tool": step.tool,
                    "command": step.command,
                    "description": step.description,
                    "requires": step.requires
                }
                for step in self.steps
            ],
            "created_at": self.created_at.isoformat(),
            "last_run": self.last_run.isoformat() if self.last_run else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Workflow':
        workflow = cls(data["name"], data["description"], data["category"])
        for step_data in data["steps"]:
            step = WorkflowStep(
                step_data["tool"],
                step_data["command"],
                step_data["description"],
                step_data.get("requires", [])
            )
            workflow.add_step(step)
        workflow.created_at = datetime.fromisoformat(data["created_at"])
        if data["last_run"]:
            workflow.last_run = datetime.fromisoformat(data["last_run"])
        return workflow

class WorkflowManager:
    """Manages tool workflows and their execution"""
    
    COMMON_WORKFLOWS = {
        "network_recon": {
            "name": "Network Reconnaissance",
            "description": "Basic network reconnaissance workflow",
            "category": "information_gathering",
            "steps": [
                {
                    "tool": "nmap",
                    "command": "nmap -sn {target_network}",
                    "description": "Discover live hosts",
                    "requires": []
                },
                {
                    "tool": "nmap",
                    "command": "nmap -sV -sC -O {live_hosts}",
                    "description": "Service and OS detection",
                    "requires": ["nmap"]
                }
            ]
        },
        "web_scan": {
            "name": "Web Application Scan",
            "description": "Basic web application security scan",
            "category": "web_applications",
            "steps": [
                {
                    "tool": "nikto",
                    "command": "nikto -h {target_url}",
                    "description": "Basic web vulnerability scan",
                    "requires": ["nikto"]
                },
                {
                    "tool": "dirb",
                    "command": "dirb {target_url}",
                    "description": "Directory enumeration",
                    "requires": ["dirb"]
                }
            ]
        }
    }
    
    def __init__(self, workflow_dir: str = "workflows"):
        self.workflow_dir = Path(workflow_dir)
        self.workflow_dir.mkdir(exist_ok=True)
        self.workflows: Dict[str, Workflow] = {}
        self.load_workflows()
    
    def create_workflow(self, name: str, description: str, category: str) -> Workflow:
        """Create a new workflow"""
        workflow = Workflow(name, description, category)
        self.workflows[name] = workflow
        return workflow
    
    def save_workflow(self, workflow: Workflow) -> None:
        """Save a workflow to file"""
        file_path = self.workflow_dir / f"{workflow.name.lower().replace(' ', '_')}.json"
        with open(file_path, 'w') as f:
            json.dump(workflow.to_dict(), f, indent=2)
    
    def load_workflows(self) -> None:
        """Load all workflows from files"""
        for file_path in self.workflow_dir.glob("*.json"):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    workflow = Workflow.from_dict(data)
                    self.workflows[workflow.name] = workflow
            except Exception as e:
                print(f"Error loading workflow {file_path}: {e}")
    
    def get_workflow(self, name: str) -> Optional[Workflow]:
        """Get a workflow by name"""
        return self.workflows.get(name)
    
    def list_workflows(self, category: Optional[str] = None) -> List[Workflow]:
        """List all workflows, optionally filtered by category"""
        if category:
            return [w for w in self.workflows.values() if w.category == category]
        return list(self.workflows.values())
    
    def create_workflow_from_template(self, template_name: str, **kwargs) -> Optional[Workflow]:
        """Create a workflow from a template"""
        template = self.COMMON_WORKFLOWS.get(template_name)
        if not template:
            return None
        
        workflow = self.create_workflow(
            template["name"],
            template["description"],
            template["category"]
        )
        
        for step_data in template["steps"]:
            # Format command with provided kwargs
            command = step_data["command"].format(**kwargs)
            step = WorkflowStep(
                step_data["tool"],
                command,
                step_data["description"],
                step_data["requires"]
            )
            workflow.add_step(step)
        
        return workflow
    
    def validate_workflow(self, workflow: Workflow, available_tools: List[str]) -> bool:
        """Validate if all required tools for a workflow are available"""
        for step in workflow.steps:
            if step.tool not in available_tools:
                return False
            for req in step.requires:
                if req not in available_tools:
                    return False
        return True 