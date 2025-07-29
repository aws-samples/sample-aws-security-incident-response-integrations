# Python Virtual Environment Rules

## Autopilot Python Execution

When running Python commands in autopilot mode, ALWAYS use a virtual environment to ensure dependency isolation and avoid conflicts with system Python packages.

### Required Patterns

1. **Before any Python command execution**, check if a virtual environment exists:
   ```bash
   # Check for existing venv
   if [ ! -d "venv" ]; then
       python3 -m venv venv
   fi
   ```

2. **Always activate the virtual environment** before running Python commands:
   ```bash
   # Activate virtual environment
   source venv/bin/activate
   ```

3. **Use the virtual environment Python** for all operations:
   ```bash
   # Install dependencies
   pip install -r requirements.txt
   
   # Run Python scripts
   python app.py
   python run_test.py
   
   # Run CDK commands
   npx cdk synth --app "python app.py"
   ```

### Virtual Environment Setup Commands

```bash
# Create virtual environment if it doesn't exist
python3 -m venv .venv

# Activate virtual environment (required before any Python operations)
source venv/bin/activate

# Install project dependencies
pip install -r requirements.txt

# Install development dependencies (if needed)
pip install -r requirements-dev.txt

# Verify virtual environment is active
which python  # Should show venv/bin/python
```

### Mandatory Checks

- **Never run `pip install` without activating venv first**
- **Never run Python scripts directly without venv activation**
- **Always verify venv is active before dependency installation**
- **Create venv if it doesn't exist before any Python operations**

### Exception Handling

If virtual environment creation fails:
1. Check Python 3 installation: `python3 --version`
2. Ensure venv module is available: `python3 -m venv --help`
3. Try alternative: `virtualenv venv` (if virtualenv is installed)

This ensures consistent, isolated Python execution environments for all autopilot operations.