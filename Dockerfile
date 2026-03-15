# Use Python base image
FROM python:3.10

# Prevent Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE 1

# Prevent Python from buffering stdout/stderr
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Upgrade pip
RUN pip install --upgrade pip

# Install dependencies
RUN pip install -r requirements.txt

# Go to Django project folder
WORKDIR /app/api

# Collect static files
RUN python manage.py collectstatic --noinput || true

# Expose port
EXPOSE 8000

# Start Django with Gunicorn
CMD ["gunicorn", "api.wsgi:application", "--bind", "0.0.0.0:8000"]