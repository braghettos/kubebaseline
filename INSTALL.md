# Installation Guide

## Prerequisites

- Python 3.8 or higher
- Access to a Kubernetes cluster (via kubeconfig)
- `pip` package manager

## Installation Steps

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Install the Package

```bash
# Install in development mode (recommended)
pip install -e .

# Or install directly
pip install .
```

### 3. Verify Installation

```bash
kbase --help
kbase version
```

## Quick Test

```bash
# Make sure you have a kubeconfig configured
kubectl cluster-info

# Run a quick scan
kbase report --output test-report.md
```

## Troubleshooting

### Import Errors

If you encounter import errors, make sure you've installed all dependencies:

```bash
pip install --upgrade -r requirements.txt
```

### Permission Errors

Ensure your kubeconfig has read permissions:

```bash
kubectl get pods --all-namespaces
```

If this fails, fix your kubeconfig permissions first.

### Module Not Found

If `kbase` command is not found after installation:

1. Make sure your Python environment is activated
2. Check that the script is in your PATH:
   ```bash
   which kbase
   ```
3. Reinstall the package:
   ```bash
   pip install --force-reinstall -e .
   ```
