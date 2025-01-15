# Project Structure

```
kali-auto/
├── kali_agent.py         # Main agent implementation
├── ai_handler_v2.py      # GPT-4 interaction handler
├── console_analyzer.py   # Tool output analysis
├── tool_discovery.py     # Tool detection and categorization
├── workflow_manager.py   # Workflow management
├── workflow_planner.py   # Workflow planning and validation
├── config/
│   └── config.yaml      # Main configuration file
├── requirements.txt      # Python dependencies
├── .env.example         # Example environment variables
├── .env                 # Environment variables (not tracked)
├── .gitignore          # Git ignore rules
├── README.md           # Project documentation
└── ProjectStructure.md  # This file

```

## Changelog

- [2024-03-19]: Initial project setup
  - Created main script (kali_agent.py)
  - Added configuration file (config.yaml)
  - Added requirements.txt with dependencies
  - Created documentation files (README.md, ProjectStructure.md)
  - Added environment example file (.env.example)

- [2024-03-20]: Added core components
  - Added ai_handler_v2.py for GPT-4 interaction
  - Added console_analyzer.py for output analysis
  - Added tool_discovery.py for Kali tool management
  - Added workflow_manager.py for workflow handling
  - Added workflow_planner.py for workflow planning
  - Moved config.yaml to config/ directory
  - Added .gitignore file 