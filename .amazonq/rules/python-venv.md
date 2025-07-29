# Python Virtual Environment Rules

## Mandatory Virtual Environment Usage

Always use a virtual environment for Python operations to ensure dependency isolation and avoid system Python conflicts.

## Required Setup Pattern

Before any Python command execution:

1. **Check for existing virtual environment**:
   ```bash
   if [ ! -d "venv" ]; then
       python3 -m venv venv
   fi
   ```

2. **Always activate virtual environment**:
   ```bash
   source venv/bin/activate
   ```

3. **Use virtual environment Python for all operations**:
   ```bash
   pip install -r requirements.txt    # install dependencies
   python app.py                      # run Python scripts
   python run_test.py                 # run tests
   npx cdk synth --app "python app.py"  # run CDK commands
   ```

## Virtual Environment Setup Commands

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

## Mandatory Checks

- **Never run `pip install` without activating venv first**
- **Never run Python scripts directly without venv activation**
- **Always verify venv is active before dependency installation**
- **Create venv if it doesn't exist before any Python operations**

## Exception Handling

If virtual environment creation fails:
1. Check Python 3 installation: `python3 --version`
2. Ensure venv module is available: `python3 -m venv --help`
3. Try alternative: `virtualenv venv` (if virtualenv is installed)

## Verification

Always verify virtual environment is active:
- `which python` should show path to venv/bin/python
- `pip list` should show only venv-installed packages

This ensures consistent, isolated Python execution environments for all operations.