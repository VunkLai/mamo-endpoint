pipeline: format lint test

format:
	black server --check --diff
	isort server --check-only --diff

lint:
	pylint server/*
	mypy server/

test:
	poetry run python server/manage.py check

requirements: # Generate or update requirements.txt
	poetry export -f requirements.txt --output requirements.txt

build:
	poetry install
	poetry run python server/manage.py migrate

run:
	poetry run python server/manage.py runserver
