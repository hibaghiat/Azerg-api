FROM python:3.12

WORKDIR /app

# Install pipenv
RUN pip3 install pipenv

# Copy Pipfile and Pipfile.lock
COPY ./Pipfile ./Pipfile.lock .

# Copy the templates
COPY ./app/templates/* /app/templates/

# Install dependencies using pipenv
RUN pipenv install --deploy --system

# Copy the rest of the application
COPY . /app

# Change script permissions
RUN chmod +x ./scripts/*

# Specify the command to run the application
CMD ["./scripts/start.dev.sh"]