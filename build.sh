#!/usr/bin/env bash
# exit on error
set -o errexit

pip install -r requirements.txt

python manage.py collectstatic --no-input
python manage.py migrate

# Create the superuser automatically using Render's Environment Variables
# The '|| true' prevents the script from crashing on future deploys when the user already exists!
python manage.py createsuperuser --noinput || true