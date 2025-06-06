#!/bin/bash

# Docker file generators

# Generate Dockerfile
generate_dockerfile() {
    cat > Dockerfile << EOF
FROM python:$PYTHON_VERSION-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF
}

# Generate docker-compose.yml
generate_docker_compose() {
    local db_name=$(echo "$PROJECT_DIR" | sed 's/-/_/g')_db
    
    cat > docker-compose.yml << EOF
version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DEBUG=true
      - POSTGRES_SERVER=db
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=$db_name
      - JWT_SECRET_KEY=your-super-secret-jwt-key-change-this-in-production
      - REDIS_HOST=redis
    depends_on:
      - db
      - redis
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=$db_name
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    restart: unless-stopped

volumes:
  postgres_data:
EOF
}

# Generate .dockerignore
generate_dockerignore() {
    cat > .dockerignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so

# Virtual Environment
venv/
env/
ENV/

# Environment variables
.env.local
.env.production

# IDEs
.vscode/
.idea/
*.swp
*.swo

# Git
.git/
.gitignore

# Logs
logs/
*.log

# Database
*.db
*.sqlite

# OS
.DS_Store
Thumbs.db

# Documentation
README.md
docs/

# Tests
tests/
pytest.ini
.coverage

# Development files
docker-compose.override.yml
alembic/versions/*.py
!alembic/versions/__init__.py

# Node modules (if any)
node_modules/
EOF
}