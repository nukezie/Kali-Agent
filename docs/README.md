# Kali Linux AI Agent 🤖

An intelligent agent powered by GPT-4 that automates and enhances Kali Linux security tools usage through natural language processing and smart workflow management.

## ⚠️ Development Status

**Note: This project is currently in active development and NOT fully functional.** While core components like the AI handler and console analyzer are implemented, many features are still being developed and debugged. You can test the current functionality by running:

```bash
python test_ai_handler_v2.py
```

Known limitations:
- Command execution needs further refinement
- Error handling requires more robust implementation
- Tool discovery system needs enhancement
- Workflow management requires additional testing
- Security measures need thorough review

## 🧠 Design & Architecture

### Core Features
- **Intelligent Tool Discovery**: Automatically detects and categorizes available Kali Linux tools
- **Smart Output Analysis**: Uses NLP and GPT-4 to analyze tool outputs and provide meaningful insights
- **Workflow Automation**: Creates and manages security testing workflows based on user objectives
- **Error Recovery**: Automatically suggests fixes for common errors and provides recovery options
- **Context-Aware**: Maintains context across tool executions and adapts responses accordingly

### System Architecture Flow
```
┌─────────────────────────────────────────────────────────────────────┐
│                        Kali Linux AI Agent                          │
├─────────────────┬─────────────────────────────┬───────────────────┤
│   Input Layer   │     Processing Layer         │   Execution Layer │
│                 │                              │                   │
│  Natural Lang.  │     Context Analysis         │   Command Gen.    │
│    Input        │           ↓                  │        ↓         │
│      ↓          │     Intent Recognition       │   Validation     │
│  Context        │           ↓                  │        ↓         │
│  Collection     │     Tool Discovery           │   Execution      │
│      ↓          │           ↓                  │        ↓         │
│  History &      │     Workflow Planning        │   Monitoring     │
│  State          │           ↓                  │        ↓         │
│                 │     Output Analysis          │   Feedback       │
└─────────┬───────┴──────────────┬──────────────┴────────┬──────────┘
          │                      │                       │
          ↓                      ↓                       ↓
    User Feedback          State Updates           System Logs
```

### Natural Language Processing Flow
```
User Input → Context Analysis → Intent Recognition → Tool Selection → Command Generation
     ↑          |                     |                   |               |
     |          ↓                     ↓                   ↓               ↓
     |     Context State      Security Checks      Tool Discovery    Parameter Gen
     |          |                     |                   |               |
     |          ↓                     ↓                   ↓               ↓
     └──────────┴─────────────────────┴───────────────────┴───────────────┘
                            Feedback & Adaptation Loop
```

### Workflow Process

1. **Context Understanding**
   ```python
   User: "Find SQL injection vulnerabilities in the admin panel I discovered at target.com/admin"
   
   Context Extraction:
   - Target: target.com/admin
   - Previous Discovery: Admin panel location
   - Intent: SQL injection testing
   - Scope: Focused on admin panel
   ```

2. **Intent Analysis & Tool Selection**
   ```python
   Intent Classification:
   - Primary: Vulnerability Assessment
   - Sub-type: SQL Injection
   - Phase: Exploitation
   
   Tool Selection Criteria:
   - Capability: SQL injection testing
   - Precision: High (specific target)
   - Prior Success: Tool history analysis
   ```

3. **Dynamic Workflow Evolution**
   ```python
   Initial Workflow:
   1. Verify target accessibility
   2. Analyze form parameters
   3. Test SQL injection vectors
   
   Adaptation Triggers:
   - New attack surface discovery
   - Error patterns
   - Success patterns
   - Resource constraints
   ```

### Command Generation & Execution Flow

The agent follows a systematic approach to generate and execute commands:

1. **Command Generation**
   ```python
   Input Analysis:
   - User intent: "Test SQL injection"
   - Context: Web application testing
   - Target: target.com/admin
   
   Tool Selection:
   - Primary: sqlmap
   - Fallback: manual SQL injection
   
   Parameter Generation:
   - Base command: sqlmap
   - Target URL: -u "target.com/admin"
   - Options: --forms --batch
   - Safety flags: --random-agent --delay 2
   ```

2. **Pre-execution Validation**
   ```python
   Safety Checks:
   - Target in scope
   - Command syntax valid
   - Required permissions available
   - Resource requirements met
   
   Risk Assessment:
   - Impact evaluation
   - Rate limiting check
   - Concurrent operations
   ```

3. **Execution Pipeline**
   ```python
   Execution Steps:
   1. Initialize command context
   2. Set up monitoring
   3. Execute with timeout
   4. Stream real-time output
   5. Analyze interim results
   6. Adjust parameters if needed
   
   Monitoring Points:
   - CPU/Memory usage
   - Network activity
   - Target responsiveness
   - Error conditions
   ```

4. **Output Processing**
   ```python
   Analysis Layers:
   1. Raw output capture
   2. Pattern matching
   3. NLP analysis
   4. Context integration
   
   Result Categories:
   - Findings (vulnerabilities, info)
   - Errors (technical, permission)
   - Warnings (stability, performance)
   - Status updates (progress, completion)
   ```

### Command Execution System

1. **Pre-Execution Analysis**
   ```python
   Command Context:
   - Current objective
   - System state
   - Previous command results
   - Resource availability
   ```

2. **Real-time Monitoring**
   ```python
   Execution Metrics:
   - Performance impact
   - Success indicators
   - Error patterns
   - Output analysis
   ```

3. **Post-Execution Learning**
   ```python
   Knowledge Update:
   - Command effectiveness
   - Error patterns
   - Success patterns
   - Context relationships
   ```

### Error Recovery Example
```python
Error Scenario:
- Command: sqlmap -u "target.com/login" --forms
- Error: Connection refused

Recovery Plan:
1. Check target availability
2. Verify network connectivity
3. Adjust timeout settings
4. Retry with reduced concurrency
```

### Adaptive Behavior System

The agent uses multiple layers of adaptation:

1. **Tactical Adaptation**
   - Immediate response to errors
   - Command parameter adjustment
   - Resource usage optimization

2. **Strategic Adaptation**
   - Workflow path modification
   - Tool selection refinement
   - Objective reprioritization

3. **Learning Adaptation**
   - Pattern recognition improvement
   - Context understanding enhancement
   - Command effectiveness learning

## 🎯 Looking for Contributors!

We're actively seeking contributors to help develop and enhance various aspects of the project. Here are the key areas that need attention:

### High Priority
1. **Tool Discovery System**
   - Enhance tool categorization logic
   - Implement automatic tool capability detection
   - Add support for custom tool definitions

2. **Workflow Engine**
   - Implement dynamic workflow adjustment based on results
   - Add parallel execution capabilities
   - Enhance error recovery mechanisms

3. **Natural Language Processing**
   - Improve context understanding
   - Enhance security intent recognition
   - Implement better parameter extraction from user input

### Medium Priority
1. **Console Analysis**
   - Expand pattern matching capabilities
   - Improve error classification
   - Add more tool-specific output parsers

2. **Security Enhancements**
   - Implement command sandboxing
   - Add permission management
   - Enhance audit logging

### Low Priority
1. **User Interface**
   - Add web interface
   - Implement real-time progress visualization
   - Create interactive workflow editor

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

## Testing Current Functionality 🧪

To test the current implementation:

```bash
# Test AI handler functionality
python test_ai_handler_v2.py

# Expected Output:
- Basic interaction test (GPT-4 responses)
- Error handling test
- Security audit test
- Conversation state test
- Token tracking test
```

## Project Structure 🗂️
```
KALI-AUTO/
├── config/
│   └── config.yaml         # Main configuration settings
├── docs/
│   ├── LICENSE            # MIT License
│   └── README.md          # Documentation
├── tests/
│   └── test_ai_handler_v2.py  # AI handler tests
├── ai_handler_v2.py       # GPT-4 interaction handler
├── console_analyzer.py    # Tool output analysis
├── kali_agent.py         # Main agent implementation
├── tool_discovery.py     # Tool detection and categorization
├── workflow_manager.py   # Workflow management
├── workflow_planner.py   # Workflow planning and validation
├── .env                  # Environment variables (not tracked)
├── .env.example         # Example environment variables
├── ProjectStructure.md  # File structure documentation
├── README.md           # Project documentation
└── requirements.txt    # Python dependencies
```

## Development 🛠️

### Getting Started with Development

1. **Set Up Development Environment**
   ```bash
   # Clone the repository
   git clone https://github.com/yourusername/kali-auto.git
   cd kali-auto
   
   # Create virtual environment
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   .\venv\Scripts\activate  # Windows
   
   # Install development dependencies
   pip install -r requirements.txt
   ```

2. **Choose a Development Area**
   - Review the "Looking for Contributors" section
   - Check existing issues on GitHub
   - Create a new issue for your proposed changes

3. **Development Guidelines**
   - Follow PEP 8 style guide
   - Add type hints to new code
   - Include docstrings and comments
   - Write unit tests for new features
   - Update documentation

### Running Tests
```bash
# Test AI handler
python test_ai_handler_v2.py

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
