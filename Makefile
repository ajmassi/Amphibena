.PHONY: isort, flake8, black, bandit
isort:
	poetry run isort --check --diff .

flake8:
	poetry run flake8 . --count --select=B,C,E,F,W,T4,B9 --max-complexity=18 --ignore=B950,E402,E203,E266,E501,W503,F403,F401 --show-source --statistics

black:
	poetry run black .

bandit:
	poetry run bandit -c "pyproject.toml" --recursive .
