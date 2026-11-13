# Contributing to DeepShield

Thank you for your interest in contributing to **DeepShield**! Contributions, bug reports, documentation improvements, testing, and thoughtful feature suggestions are welcome.

DeepShield is an educational and research-oriented network intrusion detection project. It is not a production-certified IDS.

## Before you start

- Read the [README](README.md) to understand the project, setup, architecture, and limitations.
- Check the existing issues and pull requests to avoid duplicating work.
- For a significant change, open an issue first to discuss the proposed approach.

## Ways to contribute

You can help by:

- Reporting reproducible bugs.
- Improving documentation and setup instructions.
- Adding or improving tests.
- Improving flow processing, feature extraction, model evaluation, or dashboard usability.
- Suggesting enhancements to accessibility, reliability, and explainability.

## Development setup

1. Fork this repository on GitHub.
2. Clone your fork:

   ```powershell
   git clone https://github.com/<your-username>/DeepShield.git
   cd DeepShield
   ```

3. Create and activate a virtual environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

Some workflows require locally prepared CIC-IDS2017 data, trained model artifacts, or packet-capture dependencies. These are not necessarily included in a fresh clone. Follow the README and do not commit datasets or generated model files unless the maintainers explicitly request them.

## Make your changes

1. Create a focused branch:

   ```powershell
   git checkout -b feature/short-description
   ```

2. Keep changes focused and follow the existing project structure and coding style.
3. Add or update tests when changing behavior.
4. Update documentation when commands, configuration, features, or limitations change.
5. Avoid unrelated formatting changes.

## Run tests

Before opening a pull request, run the relevant tests available for your change:

```powershell
python -m pytest tests/test_api.py -v
```

For changes involving live flow processing or feature extraction, also run the applicable validation scripts when their dependencies are installed:

```powershell
python capture/test_flows.py
python capture/test_feature_extractor.py
```

If a test cannot be run because required data, model artifacts, permissions, or dependencies are unavailable, mention that clearly in your pull request.

## Commit and open a pull request

Use a clear commit message describing the change, for example:

```powershell
git add .
git commit -m "Improve flow feature validation"
git push origin feature/short-description
```

Then open a pull request against the `main` branch. Include:

- What you changed and why.
- Related issue number, if applicable.
- How you tested the change.
- Screenshots or sample output for dashboard/UI changes.
- Any known limitations or follow-up work.

A maintainer may ask for changes before merging.

## Security and responsible use

- Only capture or analyze traffic from systems and networks you own or are explicitly authorized to monitor.
- Do not submit real personal data, credentials, tokens, private packet captures, or confidential network logs in issues or pull requests.
- Do not commit API keys, passwords, secrets, local environment files, raw datasets, or generated runtime logs.
- When reporting a potential security vulnerability, do not publish exploit details or sensitive information in a public issue. Contact the repository maintainer privately through the GitHub profile.

## Model and evaluation changes

DeepShield's predictions are experimental and depend on the training data and feature extraction process. If you change models, features, thresholds, or evaluation code:

- Describe the dataset and evaluation split used.
- Report relevant metrics, including precision, recall, and false-positive behavior where applicable.
- Avoid comparing results from different evaluation setups as if they were directly equivalent.
- Document changes that may affect compatibility with existing model artifacts or live feature extraction.

## Code of conduct

Be respectful, constructive, and welcoming. Focus feedback on the work, assume good intent, and help keep discussions useful for everyone.

Thank you for helping improve DeepShield!
