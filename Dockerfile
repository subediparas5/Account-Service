# Use an official Python 3.12 runtime as a parent image
FROM python:3.12-slim

# Install system dependencies for MySQL and build tools
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /

# Copy the requirements file to the working directory
COPY ./requirements.txt .

# Install required Python packages including debugpy
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Copy the rest of the application code to the working directory
COPY app ./app

# Expose both FastAPI and debugpy ports
EXPOSE 8000 5678

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
