.PHONY: install test coverage lint security clean all

install:
	pip install -r requirements.txt

test:
	python -m pytest tests/ -v

coverage:
	python -m pytest tests/ -v --cov=src --cov-report=term-missing --cov-report=html

lint:
	python -m ruff check src/ tests/ --ignore E501
	python -m mypy src/ --ignore-missing-imports

security:
	python -m bandit -r src/ -ll

clean:
	rm -rf htmlcov/ .coverage .pytest_cache/
	find . -name "*.pyc" -delete

all: install lint security test