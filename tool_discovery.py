#!/usr/bin/env python3

import subprocess
import json
import os
import re
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import shutil

class KaliToolDiscovery:
    """Discovers and catalogs available Kali Linux tools"""
    
    TOOL_PATHS = [
        "/usr/share",  # Main Kali tools directory
        "/usr/bin",    # Binary executables
        "/usr/sbin"    # System binaries
    ]
    
    # Base categories for tool classification
    BASE_CATEGORIES_FILE = "base_categories.json"
    
    def __init__(self):
        self.available_tools: Dict[str, Dict] = {}
        self.tool_paths: Dict[str, str] = {}
        self.discovered_tools: Set[str] = set()
        self.base_categories: Dict[str, List[str]] = self.load_base_categories()
        self.new_tools: List[Dict] = []
    
    def load_base_categories(self) -> Dict[str, List[str]]:
        """Load base categories from JSON file or create default"""
        if os.path.exists(self.BASE_CATEGORIES_FILE):
            try:
                with open(self.BASE_CATEGORIES_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading base categories: {e}")
        
        # Default categories if file doesn't exist
        default_categories = {
            "information_gathering": ["nmap", "dmitry", "maltego"],
            "vulnerability_analysis": ["nikto", "nessus", "sqlmap"],
            "wireless_attacks": ["aircrack-ng", "kismet", "wifite"],
            "web_applications": ["burpsuite", "sqlmap", "dirb"],
            "exploitation_tools": ["metasploit", "searchsploit", "msfconsole"],
            "sniffing_spoofing": ["wireshark", "ettercap", "responder"],
            "post_exploitation": ["empire", "weevely", "proxychains"],
            "forensics": ["autopsy", "binwalk", "foremost"],
            "reporting": ["cutycapt", "recordmydesktop", "dradis"],
            "reverse_engineering": ["radare2", "ghidra", "gdb"],
            "stress_testing": ["siege", "slowhttptest", "hping3"],
            "password_attacks": ["hashcat", "john", "hydra"],
            "maintaining_access": ["cryptcat", "weevely", "httptunnel"],
            "hardware_hacking": ["android-sdk", "arduino", "binwalk"]
        }
        
        # Save default categories
        with open(self.BASE_CATEGORIES_FILE, 'w') as f:
            json.dump(default_categories, f, indent=2)
        
        return default_categories
    
    def save_base_categories(self) -> None:
        """Save updated base categories to JSON file"""
        with open(self.BASE_CATEGORIES_FILE, 'w') as f:
            json.dump(self.base_categories, f, indent=2)
    
    def scan_directory(self, directory: str) -> Set[str]:
        """Scan a directory for potential tools"""
        tools = set()
        try:
            for root, dirs, files in os.walk(directory):
                # Skip hidden directories and common excludes
                dirs[:] = [d for d in dirs if not d.startswith('.') and
                          d not in ['doc', 'man', 'locale', 'icons']]
                
                # Look for executables and tool directories
                for item in dirs + files:
                    if item.startswith('.'):
                        continue
                    
                    full_path = os.path.join(root, item)
                    
                    # Check if it's an executable
                    if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                        tools.add(item)
                    
                    # Check if it's a tool directory
                    if os.path.isdir(full_path):
                        # Check for tool-specific files or directories
                        tool_indicators = ['bin', 'scripts', 'exploits', 'tools']
                        if any(os.path.exists(os.path.join(full_path, ind)) for ind in tool_indicators):
                            tools.add(item)
        except Exception as e:
            print(f"Error scanning directory {directory}: {e}")
        
        return tools
    
    def find_uncategorized_tools(self) -> List[Dict]:
        """Find tools that aren't in any base category"""
        uncategorized = []
        all_known_tools = set()
        
        # Collect all known tools from base categories
        for tools in self.base_categories.values():
            all_known_tools.update(tools)
        
        # Find tools that aren't categorized
        for tool_name, tool_info in self.available_tools.items():
            if tool_name not in all_known_tools:
                # Get tool description and help for better categorization
                description = tool_info.get('description', '')
                help_text = tool_info.get('help', '')
                
                uncategorized.append({
                    'name': tool_name,
                    'path': tool_info['path'],
                    'description': description,
                    'help': help_text
                })
        
        return uncategorized
    
    def get_tool_details(self, tool_path: str) -> Dict[str, str]:
        """Get comprehensive tool details"""
        details = {
            'description': '',
            'help': '',
            'version': ''
        }
        
        # Try to get version
        try:
            for flag in ['--version', '-V', 'version']:
                result = subprocess.run(
                    [tool_path, flag],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    details['version'] = result.stdout.split('\n')[0].strip()
                    break
        except:
            pass
        
        # Try to get help/description
        try:
            for flag in ['--help', '-h', 'help']:
                result = subprocess.run(
                    [tool_path, flag],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0 or result.stderr:
                    output = result.stdout or result.stderr
                    # Extract first meaningful line as description
                    lines = [l.strip() for l in output.split('\n') if l.strip()]
                    for line in lines:
                        if not line.startswith('-') and not line.startswith('Usage'):
                            details['description'] = line[:200]
                            break
                    details['help'] = output
                    break
        except:
            pass
        
        return details
    
    def discover_tools(self) -> None:
        """Discover tools from all paths"""
        # First scan all paths
        for path in self.TOOL_PATHS:
            if os.path.exists(path):
                discovered = self.scan_directory(path)
                self.discovered_tools.update(discovered)
        
        # Process discovered tools
        for tool_name in self.discovered_tools:
            tool_path = self.find_tool_path(tool_name)
            if tool_path:
                # Get tool details
                details = self.get_tool_details(tool_path)
                
                # Store tool information
                self.available_tools[tool_name] = {
                    "name": tool_name,
                    "path": tool_path,
                    "version": details['version'],
                    "description": details['description'],
                    "help": details['help'],
                    "installed": True
                }
                self.tool_paths[tool_name] = tool_path
        
        # Find uncategorized tools
        self.new_tools = self.find_uncategorized_tools()
    
    def create_categorization_prompt(self, tool_info: Dict) -> str:
        """Create a prompt for GPT-4 to categorize a tool"""
        prompt = f"""Please categorize this Kali Linux tool into one of the following categories:

Tool Name: {tool_info['name']}
Path: {tool_info['path']}
Description: {tool_info['description']}

Available Categories:
{json.dumps(list(self.base_categories.keys()), indent=2)}

Please respond with only the category name that best fits this tool.
If you're unsure, respond with "uncategorized".

Base your decision on:
1. The tool's name and path
2. The tool's description and help text
3. Common usage patterns in security testing
4. Similar tools in the same category

Response format: <category_name>"""
        
        return prompt
    
    def add_tool_to_category(self, tool_name: str, category: str) -> None:
        """Add a tool to a base category"""
        if category in self.base_categories:
            if tool_name not in self.base_categories[category]:
                self.base_categories[category].append(tool_name)
                self.save_base_categories()
    
    def scan_for_tools(self) -> Tuple[Dict[str, Dict], List[Dict]]:
        """Main method to scan and catalog all tools"""
        self.discover_tools()
        return self.available_tools, self.new_tools
    
    def find_tool_path(self, tool_name: str) -> Optional[str]:
        """Find the path of a tool using 'which' command"""
        try:
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def get_tool_version(self, tool_path: str, tool_name: str) -> Optional[str]:
        """Get tool version using --version or -V flags"""
        try:
            for flag in ["--version", "-V", "-version", "version"]:
                result = subprocess.run(
                    [tool_path, flag],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return result.stdout.split('\n')[0].strip()
        except Exception:
            pass
        return None
    
    def get_tool_help(self, tool_path: str, tool_name: str) -> Optional[str]:
        """Get tool help using --help flag"""
        try:
            result = subprocess.run(
                [tool_path, "--help"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 or result.stderr:
                return (result.stdout or result.stderr).strip()
        except Exception:
            pass
        return None
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict]:
        """Get information about a specific tool"""
        return self.available_tools.get(tool_name)
    
    def get_category_tools(self, category: str) -> List[Dict]:
        """Get all available tools in a specific category"""
        return [
            tool for tool in self.available_tools.values()
            if tool["category"] == category
        ]
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a specific tool is available"""
        return tool_name in self.available_tools
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get the path of a specific tool"""
        return self.tool_paths.get(tool_name)
    
    def save_tool_catalog(self, file_path: str = "tool_catalog.json") -> None:
        """Save the tool catalog to a JSON file"""
        with open(file_path, 'w') as f:
            json.dump(self.available_tools, f, indent=2)
    
    def load_tool_catalog(self, file_path: str = "tool_catalog.json") -> None:
        """Load the tool catalog from a JSON file"""
        if Path(file_path).exists():
            with open(file_path, 'r') as f:
                self.available_tools = json.load(f)
                self.tool_paths = {
                    name: info["path"]
                    for name, info in self.available_tools.items()
                }
    
    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Get system information"""
        info = {}
        try:
            # Get Kali version
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('VERSION='):
                        info['kali_version'] = line.split('=')[1].strip().strip('"')
                        break
        except Exception:
            info['kali_version'] = "Unknown"
        
        try:
            # Get kernel version
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
            info['kernel_version'] = result.stdout.strip()
        except Exception:
            info['kernel_version'] = "Unknown"
        
        return info 