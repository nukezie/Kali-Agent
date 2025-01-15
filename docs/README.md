# Kali Linux AI Agent 🤖

An intelligent agent powered by GPT-4 that automates and enhances Kali Linux security tools usage through natural language processing and smart workflow management.

## Features 🌟

- **Intelligent Tool Discovery**: Automatically detects and categorizes available Kali Linux tools
- **Smart Output Analysis**: Uses NLP and GPT-4 to analyze tool outputs and provide meaningful insights
- **Workflow Automation**: Creates and manages security testing workflows based on user objectives
- **Error Recovery**: Automatically suggests fixes for common errors and provides recovery options
- **Context-Aware**: Maintains context across tool executions and adapts responses accordingly

## Components 🔧

- **AI Handler**: Manages interactions with GPT-4 API
- **Console Analyzer**: Processes tool outputs using NLP and pattern matching
- **Tool Discovery**: Identifies and categorizes available security tools
- **Workflow Manager**: Creates and executes security testing workflows

## Installation 🚀

1. Clone the repository:
```bash
git clone https://github.com/yourusername/kali-auto.git
cd kali-auto
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your OpenAI API key
```

4. Install SpaCy language model:
```bash
python -m spacy download en_core_web_sm
```

## Usage 💻

1. Start the agent:
```bash
python kali_agent.py
```

2. Run tests:
```bash
python test_ai_handler_v2.py  # Test AI handler functionality
python test_console_analyzer.py  # Test console output analysis
```

3. Example commands:
```
> Scan target for web vulnerabilities
> Create a network reconnaissance workflow
> Analyze previous scan results
```

## Configuration ⚙️

- `config/config.yaml`: Main configuration file
- `.env`: Environment variables and API keys
- `patterns/`: Custom pattern definitions for tool output analysis

## Project Structure 🗂️
```
kali-auto/
├── kali_agent.py         # Main agent implementation
├── ai_handler_v2.py      # GPT-4 interaction management
├── console_analyzer.py   # Tool output analysis
├── tool_discovery.py     # Tool detection and categorization
├── workflow_manager.py   # Workflow handling
├── config/
│   ├── config.yaml      # Configuration settings
│   └── patterns/        # Pattern definitions
├── tests/
│   ├── test_ai_handler_v2.py
│   ├── test_console_analyzer.py
│   └── test_workflow_manager.py
└── docs/                # Documentation
```

## Development 🛠️

### Running Tests
```bash
# Run individual test files
python tests/test_ai_handler_v2.py
python tests/test_console_analyzer.py
python tests/test_workflow_manager.py

# Run with coverage report
coverage run -m pytest tests/
coverage report
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License 📄

MIT License - see LICENSE file for details

## Acknowledgments 🙏

- OpenAI GPT-4 API
- Kali Linux Team
- SpaCy NLP Library
- All contributors

## Security Notice ⚠️

This tool is intended for authorized security testing only. Always ensure you have permission to test target systems. 