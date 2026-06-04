# Local Development

## Setup

git clone https://github.com/Zi-Stonga/Regulatory-Compliance.git
cd Regulatory-Compliance
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

Edit .env and set ANTHROPIC_API_KEY.

## Running tests

make test

No AWS credentials needed. All AWS calls use moto mocks.
moto magic credentials are injected by the aws_env pytest fixture.

## Coverage report

make coverage

HTML report written to htmlcov/index.html.

## Lint

make lint

Runs ruff check and mypy.

## Security scan

make security

Runs bandit with medium and high severity reporting.

## All checks together

make all

## Adding a new framework

1. Add the framework name to _VALID_FRAMEWORKS in compliance_engine.py
2. Add the framework to configs/config.yaml frameworks list
3. Add test cases to TestValidateSqsMessage in test_compliance_engine.py
4. Update docs/specs/00_system_overview.md Frameworks Covered section

## Windows notes

- Use python -m pytest not bare pytest
- Use pathlib.Path.write_text with encoding utf-8 not cat heredocs
- Use notepad for files containing special characters
- ThreadPoolExecutor can hang in some Windows terminal environments
