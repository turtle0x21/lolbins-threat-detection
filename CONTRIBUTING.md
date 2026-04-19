# Contributing to LOLBins Threat Detection

Thank you for your interest in contributing! This project is open to anyone who wants to help improve Windows LOLBins threat detection.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Install dependencies: `pip install -r requirements.txt`
4. Create a feature branch: `git checkout -b feature/your-feature`

## Development Setup

### Prerequisites
- Windows 10/11
- Python 3.8+
- Administrator privileges (for testing Event Log monitoring)

### Running Locally
```bash
# Start the full system
python start.py

# Or run components individually
python server/app.py      # Server only
python agent/agent.py     # Agent only
```

### Training the ML Model
```bash
python server/model_trainer.py
```

## What Can You Contribute?

### 🔍 New Detection Signatures
- Add new LOLBin attack patterns to `server/detector.py`
- Reference [LOLBAS Project](https://lolbas-project.github.io/) and [MITRE ATT&CK](https://attack.mitre.org/) for techniques
- Each signature should have a descriptive name and accurate regex pattern

### 🧠 ML Model Improvements
- Add training samples to `server/model_trainer.py`
- Propose new features in `server/feature_extractor.py`
- Experiment with different classifiers or hyperparameters

### 🖥️ Dashboard Enhancements
- Improve the web UI in `web/templates/` and `web/static/`
- Add filtering, search, or export functionality
- Dark mode, charts, or timeline views

### 🧪 Testing
- Write test cases for the detection pipeline
- Create test attack samples (safe, non-destructive)
- Report false positives or false negatives

### 📝 Documentation
- Improve setup instructions
- Write tutorials or guides
- Document detection rules and their coverage

## Pull Request Process

1. **Keep PRs focused** — One feature or fix per PR
2. **Write clear commit messages** — Use conventional commits (`feat:`, `fix:`, `docs:`, etc.)
3. **Add docstrings** — Document new functions and classes
4. **Test your changes** — Make sure the detection pipeline still works
5. **Update the README** — If your change adds new features or changes behavior
6. **Describe your PR** — Explain what you changed and why

## Code Style

- Follow PEP 8 for Python code
- Use descriptive variable and function names
- Add comments for complex logic
- Keep functions focused and modular

## Reporting Bugs

Open an issue with:
- A clear, descriptive title
- Steps to reproduce the bug
- Expected vs. actual behavior
- Your OS version and Python version
- Relevant log output

## Suggesting Features

Open an issue with:
- A clear description of the feature
- Why it would be useful
- Any implementation ideas you have

## Code of Conduct

- Be respectful and constructive
- Welcome newcomers
- Focus on the technical merits of contributions
- No harassment, discrimination, or personal attacks

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
