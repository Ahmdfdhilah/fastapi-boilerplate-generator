# FastAPI Boilerplate Generator

A powerful, modular, and highly customizable generator for creating production-ready FastAPI applications with JWT authentication, database integration, and modern Python patterns.

## 🚀 Features

- **Modular Architecture**: Easily extensible with custom generators and plugins
- **Multiple Configurations**: Pre-built configs for different use cases (minimal, full-stack, microservice)
- **Production Ready**: Includes logging, error handling, security best practices, and monitoring
- **Docker Support**: Optional containerization with docker-compose
- **Modern Python**: Async/await patterns, type hints, Pydantic v2, SQLModel
- **Comprehensive Testing**: pytest setup with async support and coverage
- **Database Migrations**: Alembic integration for schema management
- **Authentication**: JWT-based authentication with role-based access control
- **API Documentation**: Auto-generated OpenAPI/Swagger documentation
- **Structured Logging**: JSON-formatted logs with rotation
- **CORS Support**: Configurable cross-origin resource sharing

## 📁 Generator Structure

```
fastapi-boilerplate-generator/
├── fastapi-generator.sh     # Main generator script
├── setup.sh                 # Setup script for initializing generator
├── Makefile                 # Build automation and shortcuts
├── config/
│   ├── default.conf         # Default configuration options
│   └── custom.conf.example  # Template for custom configurations
├── utils/
│   ├── colors.sh            # Color output utilities
│   └── helpers.sh           # Helper functions
├── generators/
│   ├── core.sh              # Core application files
│   ├── auth.sh              # Authentication system
│   ├── models.sh            # Database models
│   ├── api.sh               # API endpoints and schemas
│   ├── middleware.sh        # Custom middleware
│   ├── utils.sh             # Utility functions
│   ├── tests.sh             # Test configuration
│   ├── docker.sh            # Docker configuration
│   └── docs.sh              # Documentation generation
├── examples/
│   ├── minimal.conf         # Minimal API configuration
│   ├── full-stack.conf      # Full-featured application
│   └── microservice.conf    # Container-optimized microservice
├── templates/               # Custom templates directory
├── tests/                   # Generator tests
└── docs/                    # Additional documentation
```

## 🏁 Quick Start

### 1. Download and Setup

```bash
# Clone the generator
git clone <repository-url> fastapi-generator
cd fastapi-generator

# Run setup to create the modular structure
make setup
# or
./setup.sh
```

### 2. Generate Your First Project

```bash
# Interactive mode (recommended for first use)
./fastapi-generator.sh

# Command line mode
./fastapi-generator.sh -n my-api -a "Your Name" -e "your@email.com" --docker

# Using pre-built configurations
./fastapi-generator.sh --config examples/full-stack.conf -n my-enterprise-api

# Quick start with prompts
make quickstart
```

### 3. Run Your Generated Project

```bash
cd my-api

# With Docker (if generated with --docker)
docker-compose up --build

# Manual setup
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
python main.py
```

Your API will be available at:
- **API**: http://localhost:8000
- **Documentation**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🛠️ Usage

### Command Line Options

```bash
./fastapi-generator.sh [OPTIONS]

Options:
  -n, --name NAME           Project name
  -d, --description DESC    Project description
  -a, --author AUTHOR       Author name
  -e, --email EMAIL         Author email
  --docker                  Include Docker configuration
  --no-docker               Skip Docker configuration (default)
  --config FILE             Use custom configuration file
  -h, --help                Show help message
```

### Pre-built Configurations

#### Minimal Configuration
```bash
./fastapi-generator.sh --config examples/minimal.conf
```
- Basic FastAPI setup with authentication
- No Docker, Redis, or advanced features
- Perfect for simple APIs and learning

#### Full-stack Configuration
```bash
./fastapi-generator.sh --config examples/full-stack.conf
```
- All features enabled (Celery, WebSockets, monitoring)
- Docker support with PostgreSQL and Redis
- Production-ready with comprehensive logging
- Suitable for enterprise applications

#### Microservice Configuration
```bash
./fastapi-generator.sh --config examples/microservice.conf
```
- Optimized for containerized microservices
- Health checks, metrics, and observability
- Service mesh ready
- Perfect for cloud-native architectures

## 🔧 Customization

### Creating Custom Configurations

1. **Copy the example:**
   ```bash
   cp config/custom.conf.example config/my-project.conf
   ```

2. **Customize settings:**
   ```bash
   # Enable features you need
   INCLUDE_CELERY=true
   INCLUDE_WEBSOCKETS=true
   INCLUDE_MONITORING=true
   
   # Add custom dependencies
   ADDITIONAL_REQUIREMENTS=(
       "celery==5.3.1"
       "websockets==11.0.3"
       "prometheus-client==0.17.1"
   )
   
   # Add custom directories
   CUSTOM_DIRECTORIES=(
       "src/tasks"
       "src/websockets"
       "monitoring"
   )
   ```

3. **Use your configuration:**
   ```bash
   ./fastapi-generator.sh --config config/my-project.conf
   ```

### Adding New Features

1. **Create a new generator module:**
   ```bash
   touch generators/monitoring.sh
   ```

2. **Implement your generators:**
   ```bash
   # generators/monitoring.sh
   generate_prometheus_config() {
       cat > monitoring/prometheus.yml << 'EOF'
   global:
     scrape_interval: 15s
   scrape_configs:
     - job_name: 'fastapi-app'
       static_configs:
         - targets: ['app:8000']
   EOF
   }
   ```

3. **Update the main generator:**
   ```bash
   # Add to fastapi-generator.sh
   source "$SCRIPT_DIR/generators/monitoring.sh"
   
   # Add to generation process
   if [[ "$INCLUDE_MONITORING" == true ]]; then
       generate_prometheus_config
   fi
   ```

## 📊 Generated Project Features

### Core Features
- **FastAPI**: Modern, fast web framework
- **SQLModel**: Type-safe database models
- **Pydantic v2**: Data validation and serialization
- **Alembic**: Database migration management
- **Async/Await**: Full async support throughout

### Authentication & Security
- **JWT Authentication**: Secure token-based auth
- **Role-based Access Control**: User roles and permissions
- **Password Hashing**: Bcrypt password security
- **CORS**: Configurable cross-origin support

### Development & Testing
- **pytest**: Comprehensive test setup
- **Type Hints**: Full type safety
- **Logging**: Structured JSON logging
- **Error Handling**: Global exception handling
- **API Documentation**: Auto-generated OpenAPI docs

### Production Features
- **Docker Support**: Multi-container setup
- **Health Checks**: Application monitoring endpoints
- **Environment Configuration**: Flexible config management
- **Database Pooling**: Connection pool optimization
- **Request Logging**: Detailed request/response logging

## 🧪 Testing

### Run Generator Tests
```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests only
make test-integration

# Validate generator code
make validate

# Lint shell scripts (requires shellcheck)
make lint
```

### Test Generated Projects
```bash
# Generate demo projects
make demo

# Generate all example configurations
make examples

# Clean up test projects
make clean-examples
```

### Test a Generated Project
```bash
# After generating a project
cd my-generated-project

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest

# Run with coverage
pytest --cov=src tests/

# Test API endpoints
python -m pytest tests/test_auth.py -v
```

## 🚀 Deployment

The generator creates deployment-ready projects. See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed deployment guides:

- **Local Development**: Virtual environment setup
- **Docker**: Container-based deployment
- **VPS/Server**: Traditional server deployment
- **Cloud Platforms**: AWS ECS, Google Cloud Run, Heroku
- **Production**: Security, monitoring, and scaling considerations

### Quick Deployment Examples

#### Docker Deployment
```bash
# Generated with --docker flag
cd my-api
docker-compose up --build
```

#### Heroku Deployment
```bash
cd my-api
heroku create my-api-name
heroku addons:create heroku-postgresql:hobby-dev
git push heroku main
heroku run alembic upgrade head
```

#### VPS Deployment
```bash
# On your server
git clone <your-repo>
cd your-project
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
alembic upgrade head

# With systemd service (see DEPLOYMENT.md for full config)
sudo systemctl enable my-api
sudo systemctl start my-api
```

## 🛠️ Development Tools

### Makefile Commands
```bash
make help              # Show all available commands
make setup             # Initialize generator structure
make install           # Install generator system-wide
make test              # Run all tests
make demo              # Generate demo projects
make clean             # Clean up temporary files
make docs              # Generate documentation
make quickstart        # Interactive quick start
make stats             # Show generator statistics
```

### Development Workflow
```bash
# 1. Setup development environment
make dev-setup

# 2. Make changes to generators
vim generators/my-feature.sh

# 3. Test changes
make validate
make test

# 4. Generate test project
./fastapi-generator.sh -n test-project --config examples/minimal.conf

# 5. Test generated project
cd test-project
python -m pytest

# 6. Clean up
make clean
```

## 📚 Documentation

### Available Guides
- **[USAGE.md](USAGE.md)**: Comprehensive usage guide and customization
- **[DEPLOYMENT.md](DEPLOYMENT.md)**: Deployment scenarios and production setup
- **API Documentation**: Auto-generated for each project at `/docs`

### Generator Documentation
```bash
# Generate documentation
make docs

# View generator statistics
make stats

# Show configuration options
cat config/default.conf
```

## 🏗️ Project Structure (Generated)

When you generate a project, you get a well-organized structure:

```
my-api/
├── src/
│   ├── api/
│   │   ├── endpoints/
│   │   │   ├── auth.py          # Authentication endpoints
│   │   │   └── users.py         # User management endpoints
│   │   └── router.py            # API router configuration
│   ├── auth/
│   │   ├── jwt.py               # JWT token handling
│   │   └── permissions.py       # Authorization and permissions
│   ├── core/
│   │   ├── config.py            # Application configuration
│   │   └── database.py          # Database setup and session management
│   ├── middleware/
│   │   ├── error_handler.py     # Global error handling
│   │   └── logging.py           # Request logging middleware
│   ├── models/
│   │   ├── base.py              # Base model with common fields
│   │   └── user.py              # User and role models
│   ├── repositories/
│   │   └── user.py              # User data access layer
│   ├── schemas/
│   │   ├── common.py            # Common Pydantic schemas
│   │   └── user.py              # User schemas for validation
│   ├── services/
│   │   ├── auth.py              # Authentication business logic
│   │   └── user.py              # User management service
│   └── utils/
│       ├── logging.py           # Logging configuration utilities
│       └── validators.py        # Custom validation functions
├── tests/
│   ├── conftest.py              # Test configuration and fixtures
│   └── test_auth.py             # Authentication endpoint tests
├── alembic/                     # Database migration files
├── logs/                        # Application log files
├── docs/                        # Project documentation
├── .env                         # Environment variables (don't commit!)
├── .gitignore                   # Git ignore rules
├── main.py                      # FastAPI application entry point
├── requirements.txt             # Python dependencies
├── README.md                    # Project-specific documentation
├── Dockerfile                   # Docker container definition (optional)
├── docker-compose.yml           # Multi-container setup (optional)
└── alembic.ini                  # Alembic configuration
```

## 🔒 Security Features

### Built-in Security
- **JWT Authentication**: Secure token-based authentication
- **Password Hashing**: bcrypt for secure password storage
- **Role-based Access Control**: Flexible permission system
- **Input Validation**: Pydantic data validation
- **CORS Configuration**: Configurable cross-origin policies
- **SQL Injection Prevention**: SQLModel/SQLAlchemy protection
- **Error Information Leakage**: Secure error handling

### Security Best Practices (Implemented)
- Environment variable configuration
- Secure headers middleware
- Request logging for audit trails
- Database connection pooling
- Async operations for better performance

## 🔧 Configuration Options

### Key Configuration Variables

```bash
# Project Settings
PROJECT_NAME="my-api"
PROJECT_DESCRIPTION="My awesome API"
AUTHOR_NAME="Your Name"
AUTHOR_EMAIL="your@email.com"

# Features
INCLUDE_AUTH=true
INCLUDE_USER_MANAGEMENT=true
INCLUDE_DOCKER=true
INCLUDE_REDIS=true
INCLUDE_TESTS=true

# Database
DEFAULT_DB_TYPE="postgresql"
DEFAULT_DB_HOST="localhost"
DEFAULT_DB_PORT="5432"

# Security
DEFAULT_JWT_ALGORITHM="HS256"
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES="30"

# Additional Features
INCLUDE_RATE_LIMITING=false
INCLUDE_CELERY=false
INCLUDE_WEBSOCKETS=false
INCLUDE_MONITORING=false
```

See `config/default.conf` for all available options.

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**: Add new generators, fix bugs, improve documentation
4. **Test your changes**: `make test && make validate`
5. **Commit your changes**: `git commit -m 'Add amazing feature'`
6. **Push to the branch**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**

### Development Guidelines
- Follow existing code style and patterns
- Add tests for new features
- Update documentation for changes
- Use descriptive commit messages
- Test generated projects work correctly

### Adding New Generators
1. Create new generator file in `generators/`
2. Add configuration options to `config/default.conf`
3. Update main generator script to include new module
4. Add tests and documentation
5. Create example configuration if needed

## 📈 Roadmap

### Upcoming Features
- [ ] **Database Options**: MySQL, SQLite support
- [ ] **Authentication Providers**: OAuth2, LDAP integration
- [ ] **API Versioning**: Built-in API version management
- [ ] **Rate Limiting**: Redis-based rate limiting
- [ ] **Monitoring**: Prometheus metrics integration
- [ ] **Caching**: Redis caching layer
- [ ] **Message Queues**: Celery task integration
- [ ] **WebSockets**: Real-time communication support
- [ ] **File Upload**: S3/local file handling
- [ ] **Admin Interface**: Auto-generated admin panel

### Performance Improvements
- [ ] Parallel generation for faster project creation
- [ ] Template caching for repeated generations
- [ ] Incremental updates for existing projects

## ❓ FAQ

### General Questions

**Q: What Python versions are supported?**
A: Generated projects support Python 3.8+. We recommend Python 3.11 for best performance.

**Q: Can I modify the generated code?**
A: Absolutely! The generated code is fully yours to modify and extend.

**Q: How do I add new API endpoints?**
A: Follow the existing patterns in `src/api/endpoints/` and add your router to `src/api/router.py`.

### Configuration Questions

**Q: How do I disable certain features?**
A: Set the feature flags to `false` in your configuration file (e.g., `INCLUDE_REDIS=false`).

**Q: Can I use a different database?**
A: Currently PostgreSQL is supported. MySQL and SQLite support is planned.

**Q: How do I add custom dependencies?**
A: Add them to the `ADDITIONAL_REQUIREMENTS` array in your configuration file.

### Deployment Questions

**Q: Is the generated code production-ready?**
A: Yes, but remember to change default secrets, configure CORS properly, and set up monitoring.

**Q: How do I deploy to cloud platforms?**
A: See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed guides for AWS, Google Cloud, Heroku, and others.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **FastAPI**: For the amazing web framework
- **SQLModel**: For the elegant database ORM
- **Pydantic**: For data validation and serialization
- **Alembic**: For database migration management
- **pytest**: For the testing framework

## 📞 Support

- **Documentation**: Check [USAGE.md](USAGE.md) and [DEPLOYMENT.md](DEPLOYMENT.md)
- **Issues**: Open an issue on GitHub for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions and community support
- **Examples**: Check the `examples/` directory for configuration templates

---

**Happy coding! 🚀**

*Generated with ❤️ by FastAPI Boilerplate Generator*