#!/bin/bash

# Documentation generators

# Generate Alembic configuration
generate_alembic_config() {
    # Create alembic.ini
    cat > alembic.ini << 'EOF'
# A generic, single database configuration.

[alembic]
# path to migration scripts
script_location = alembic

# template used to generate migration file names; The default value is %%(rev)s_%%(slug)s
# Uncomment the line below if you want the files to be prepended with date and time
# file_template = %%(year)d_%%(month).2d_%%(day).2d_%%(hour).2d%%(minute).2d-%%(rev)s_%%(slug)s

# sys.path path, will be prepended to sys.path if present.
# defaults to the current working directory.
prepend_sys_path = .

# timezone to use when rendering the date within the migration file
# as well as the filename.
# If specified, requires the python-dateutil library that can be
# installed by adding `alembic[tz]` to the pip requirements
# string value is passed to dateutil.tz.gettz()
# leave blank for localtime
# timezone =

# max length of characters to apply to the
# "slug" field
# truncate_slug_length = 40

# set to 'true' to run the environment during
# the 'revision' command, regardless of autogenerate
# revision_environment = false

# set to 'true' to allow .pyc and .pyo files without
# a source .py file to be detected as revisions in the
# versions/ directory
# sourceless = false

# version path separator; As mentioned above, this is the character used to split
# version_locations. The default within new alembic.ini files is "os", which uses
# os.pathsep. If this key is omitted entirely, it falls back to the legacy
# behavior of splitting on spaces and/or commas.
# Valid values for version_path_separator are:
#
# version_path_separator = :
# version_path_separator = ;
# version_path_separator = space
version_path_separator = os

# the output encoding used when revision files
# are written from script.py.mako
# output_encoding = utf-8

sqlalchemy.url = driver://user:pass@localhost/dbname


[post_write_hooks]
# post_write_hooks defines scripts or Python functions that are run
# on newly generated revision scripts.  See the documentation for further
# detail and examples

# format using "black" - use the console_scripts runner, against the "black" entrypoint
# hooks = black
# black.type = console_scripts
# black.entrypoint = black
# black.options = -l 79 REVISION_SCRIPT_FILENAME

# Logging configuration
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
EOF

    # Create alembic/env.py
    cat > alembic/env.py << 'EOF'
"""Alembic environment configuration."""

from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import asyncio
from sqlalchemy.ext.asyncio import AsyncEngine

# Import your models here
from src.models.user import User, Role, UserRole
from src.models.base import BaseModel

# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import your SQLModel metadata
from sqlmodel import SQLModel
target_metadata = SQLModel.metadata

# Get database URL from settings
from src.core.config import settings
config.set_main_option("sqlalchemy.url", str(settings.DATABASE_URI))


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = AsyncEngine(
        engine_from_config(
            config.get_section(config.config_ini_section),
            prefix="sqlalchemy.",
            poolclass=pool.NullPool,
        )
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
EOF

    # Create alembic/script.py.mako
    cat > alembic/script.py.mako << 'EOF'
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from alembic import op
import sqlalchemy as sa
import sqlmodel
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
EOF
}

# Generate README.md
generate_readme() {
    local setup_instructions
    local usage_note
    
    if [[ "$USE_DOCKER" == true ]]; then
        setup_instructions="### With Docker

\`\`\`bash
cd $PROJECT_DIR
# Edit .env file if needed
docker-compose up --build
\`\`\`

### Alternative: Manual Setup

\`\`\`bash
cd $PROJECT_DIR
python -m venv venv
source venv/bin/activate  # On Windows: venv\\\\Scripts\\\\activate
pip install -r requirements.txt
\`\`\`"

        usage_note="## Docker Usage

The project includes Docker configuration for easy setup:

\`\`\`bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Rebuild after changes
docker-compose up --build
\`\`\`

Services included:
- **FastAPI app**: http://localhost:8000
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379"
    else
        setup_instructions="### Manual Setup

\`\`\`bash
cd $PROJECT_DIR
python -m venv venv
source venv/bin/activate  # On Windows: venv\\\\Scripts\\\\activate
pip install -r requirements.txt
\`\`\`"

        usage_note="## Manual Database Setup

You'll need to install and configure:

1. **PostgreSQL Server**
   \`\`\`bash
   # Ubuntu/Debian
   sudo apt install postgresql postgresql-contrib
   
   # macOS
   brew install postgresql
   
   # Windows: Download from postgresql.org
   \`\`\`

2. **Redis Server** (Optional)
   \`\`\`bash
   # Ubuntu/Debian
   sudo apt install redis-server
   
   # macOS
   brew install redis
   
   # Windows: Download from redis.io
   \`\`\`"
    fi

    cat > README.md << EOF
# $PROJECT_NAME

$PROJECT_DESCRIPTION

This is a FastAPI boilerplate with JWT authentication, built with modern Python async/await patterns.

## Features

- **FastAPI** - Modern, fast web framework for building APIs
- **JWT Authentication** - Secure token-based authentication
- **SQLModel** - Modern SQL databases with Python types
- **Async/Await** - Full async support with AsyncPG
- **Pydantic V2** - Data validation using Python type annotations
- **Alembic** - Database migrations
- **pytest** - Testing framework with async support
- **CORS** - Cross-Origin Resource Sharing support
- **Structured Logging** - JSON-formatted logs with rotation
- **Docker Ready** - Containerization support

## Project Structure

\`\`\`
$PROJECT_DIR/
├── src/
│   ├── api/
│   │   ├── endpoints/
│   │   │   ├── auth.py          # Authentication endpoints
│   │   │   └── users.py         # User management endpoints
│   │   └── router.py            # API router configuration
│   ├── auth/
│   │   ├── jwt.py               # JWT token handling
│   │   └── permissions.py       # Authorization logic
│   ├── core/
│   │   ├── config.py            # Application configuration
│   │   └── database.py          # Database setup
│   ├── middleware/
│   │   ├── error_handler.py     # Global error handling
│   │   └── logging.py           # Request logging
│   ├── models/
│   │   ├── base.py              # Base model with common fields
│   │   └── user.py              # User models
│   ├── repositories/
│   │   └── user.py              # User data access layer
│   ├── schemas/
│   │   ├── common.py            # Common schemas
│   │   └── user.py              # User schemas
│   ├── services/
│   │   ├── auth.py              # Authentication service
│   │   └── user.py              # User service
│   └── utils/
│       ├── logging.py           # Logging utilities
│       └── validators.py        # Validation utilities
├── tests/
│   ├── conftest.py              # Test configuration
│   └── test_auth.py             # Authentication tests
├── alembic/                     # Database migrations
├── logs/                        # Application logs
├── .env                         # Environment variables
├── main.py                      # Application entry point
└── requirements.txt             # Python dependencies
\`\`\`

## Quick Start

$setup_instructions

### 2. Configure Environment

Edit \`.env\` file with your database settings:

\`\`\`env
# Database Settings
POSTGRES_SERVER=localhost
POSTGRES_USER=your_user
POSTGRES_PASSWORD=your_password
POSTGRES_DB=your_database

# JWT Settings (Change in production!)
JWT_SECRET_KEY=your-super-secret-jwt-key-change-this-in-production
\`\`\`

### 3. Initialize Database

\`\`\`bash
# Create initial migration
alembic revision --autogenerate -m "Initial migration"

# Apply migrations
alembic upgrade head
\`\`\`

### 4. Run Application

\`\`\`bash
python main.py
\`\`\`

$usage_note

## API Endpoints

### Authentication

- \`POST /api/v1/auth/register\` - Register new user
- \`POST /api/v1/auth/login\` - Login user

### Users

- \`GET /api/v1/users/me\` - Get current user info (requires auth)

## Usage Examples

### Register a User

\`\`\`bash
curl -X POST "http://localhost:8000/api/v1/auth/register" \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123",
    "first_name": "John",
    "last_name": "Doe"
  }'
\`\`\`

### Login

\`\`\`bash
curl -X POST "http://localhost:8000/api/v1/auth/login" \\
  -H "Content-Type: application/json" \\
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123"
  }'
\`\`\`

### Access Protected Endpoint

\`\`\`bash
curl -X GET "http://localhost:8000/api/v1/users/me" \\
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
\`\`\`

## Testing

\`\`\`bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest

# Run with coverage
pytest --cov=src tests/
\`\`\`

## Database Migrations

\`\`\`bash
# Create a new migration
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head

# Rollback migration
alembic downgrade -1
\`\`\`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| \`PROJECT_NAME\` | Application name | $PROJECT_NAME |
| \`DEBUG\` | Debug mode | \`false\` |
| \`POSTGRES_SERVER\` | Database host | \`localhost\` |
| \`POSTGRES_PORT\` | Database port | \`5432\` |
| \`POSTGRES_USER\` | Database user | - |
| \`POSTGRES_PASSWORD\` | Database password | - |
| \`POSTGRES_DB\` | Database name | - |
| \`JWT_SECRET_KEY\` | JWT secret key | - |
| \`ACCESS_TOKEN_EXPIRE_MINUTES\` | Token expiry | \`30\` |
| \`CORS_ORIGINS\` | Allowed origins | \`*\` |

## Security Notes

1. **Change JWT Secret**: Always change \`JWT_SECRET_KEY\` in production
2. **CORS Configuration**: Restrict \`CORS_ORIGINS\` to your domains
3. **Password Policy**: Implement strong password requirements
4. **Rate Limiting**: Consider adding rate limiting for production
5. **HTTPS**: Always use HTTPS in production

## Development

### Adding New Features

1. **Models**: Add new models in \`src/models/\`
2. **Schemas**: Define Pydantic schemas in \`src/schemas/\`
3. **Repositories**: Add data access logic in \`src/repositories/\`
4. **Services**: Implement business logic in \`src/services/\`
5. **Endpoints**: Create API endpoints in \`src/api/endpoints/\`
6. **Tests**: Add tests in \`tests/\`

### Code Style

This project follows Python best practices:

- Type hints for all functions
- Async/await for database operations
- Proper error handling and logging
- Clean architecture with separation of concerns

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Author

$AUTHOR_NAME <$AUTHOR_EMAIL>

---

Generated by FastAPI Boilerplate Generator
EOF
}