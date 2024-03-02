<h1 align="center">time</h1>

The ReachHub RCM Backend.

- [Local Quickstart](#local-quickstart)
  - [1. Install dependencies](#1-install-dependencies)
  - [2. Set up database](#2-set-up-database)
  - [2. Run application](#2-run-application)
- [Useful commands](#useful-commands)
  - [Making a new module](#making-a-new-module)
  - [Shell shortcuts](#shell-shortcuts)
  - [Running migrations](#running-migrations)
  - [Reverting migrations](#reverting-migrations)
  - [Migration generation](#migration-generation)
  - [Running tests](#running-tests)
  - [Environments](#environments)

## Local Quickstart (MacOS)

The fastest way to get the time backend set up locally.

### 1. Install dependencies (MacOS)

There are four things to install

1. Conda
2. GCP Artifact Registry packages
3. Python libraries
4. Pre-commit hooks

Create a new miniconda environment.

```shell
conda create -n time python=3.10
conda activate time
```

Install all python libraries. Libraries related to development are kept separate, in `requirements-dev.txt`. Make sure to add any dependencies you introduce into these files!

```shell
pip install -r requirements.txt -r requirements-dev.txt -r requirements-time.txt
```

To skip failing packages while installing libraries:

```
sort requirements.txt requirements-dev.txt | uniq | xargs -n 1 pip install
```

Install `pre-commit` and spin it up:

```shell
pre-commit install
pre-commit
```

⚠️ Whenever you work on this codebase, **remember to activate the conda environment:**

```shell
conda activate time
```

### 2. Set up database

First, create your database.

```shell
createdb time_test
```

Then, create your `.env` file. Make sure to set `DB_USER` and `DB_PASSWORD` to the values on your machine.

```
RELOAD=True

DB_HOST=localhost
DB_NAME=time
DB_PORT=5432
DB_USER=<YOUR DB USERNAME>
DB_PASSWORD=<YOUR DB PASSWORD>
```

Now, let's get our database up to speed. Run all migrations with this command:

```shell
alembic upgrade head
```

If you have issues on your Mac M1 (`Symbol not found: _PQbackendPID`), follow these instructions:
https://github.com/psycopg/psycopg2/issues/1216#issuecomment-767892042

```shell
brew install libpq --build-from-source
export LDFLAGS="-L/opt/homebrew/opt/libpq/lib"

pip install psycopg2 --no-cache-dir
```

If the above doesn't work for you, Try these commands

```shell
pip uninstall psycopg2
brew install libpq
pip install psycopg2 --no-cache-dir
pip install --force psycopg2-binary
```

### 2. Run application

You're set to run the app! Make sure you're in the root directory of the project, and run:

```shell
uvicorn app.app:get_app --factory --reload
```

```shell

$ uvicorn app.app:get_app --factory
INFO:     Started server process [50449]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

Open API endpoint: `http://localhost:8000/api/docs`

Redoc endpoint: `http://localhost:8000/redoc`

## Useful commands

### Making a new module

Use the following script to make a new module. (i.e. a folder in `app/api/v1`)

It'll create all necessary files with standard imports for you!

```shell
$ scripts/new_module.sh provider  # creates app.api.v1.provider
$ tree app/api/provider        # files created
app/api/provider
├── __init__.py
├── controllers.py
├── models.py
├── schemas.py
└── automation_services.py
```

### Shell shortcuts

Make sure to add [`./shortcuts.sh`](./shortcuts.sh) to your `~/.zshrc` so that you can easily run commands!

### Running migrations

If you want to migrate your database, you should run following commands:

```bash
# To run all migrations untill the migration with revision_id.
alembic upgrade "<revision_id>"

# To perform all pending migrations.
alembic upgrade head
```

### Reverting migrations

If you want to revert migrations, you should run:

```bash
# revert all migrations up to: revision_id.
alembic downgrade <revision_id>

# Revert everything.
 alembic downgrade base
```

### Migration generation

To generate migrations you should run:

```bash
# For automatic change detection.
alembic revision --autogenerate -m "message"

# For empty file generation.
alembic revision
```

### Running tests

To run unit tests locally:

```bash
ENV=testing pytest -vv . --cov=app.api.v1 --cov-fail-under=85
```

This is the same command that runs in Github.

To run integration tests locally:

```bash
ENV=testing pytest app/integration_tests
```

## Docker

### Build

```bash
docker build -t time .
```

### Run

```bash
docker run -p 8000:8000 time
```

### Tag

  ```bash
  docker tag time gcr.io/reach-hub/time:latest
  ```

### Environments

To get project structure without env and pycache and other irrelevant files, run:

```
tree -I 'env|__pycache__|*.pyc|*.pyo|*.pyd|*.git|*.idea|*.vscode|*.DS_Store'
```