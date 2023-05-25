
requirements: # Generate or update requirements.txt
	poetry export -f requirements.txt --output requirements.txt

build:
	poetry install
	poetry run python server/manage.py migrate

run:
	poetry run python server/manage.py runserver
