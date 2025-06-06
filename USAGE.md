# Usage Guide

This guide explains how to use and customize the modular FastAPI Boilerplate Generator.

## Installation and Setup

### 1. Download the Generator

```bash
# Option 1: Clone from repository
git clone <repository-url> fastapi-generator
cd fastapi-generator

# Option 2: Download and extract zip
wget <zip-url>
unzip fastapi-generator.zip
cd fastapi-generator
```

### 2. Run Setup

```bash
# Make setup script executable and run it
chmod +x setup.sh
./setup.sh
```

This creates the complete modular structure:
- Configuration files
- Utility functions
- Generator modules
- Example configurations

### 3. Make Generator Executable

```bash
chmod +x fastapi-generator.sh
```

## Basic Usage

### Interactive Mode

Run without arguments for interactive setup:

```bash
./fastapi-generator.sh
```

You'll be prompted for:
- Project name
- Project description
- Author information
- Deployment method (Docker or manual)

### Command Line Mode

Use command line arguments for automated generation:

```bash
# Basic project
./fastapi-generator.sh -n my-api -a "John Doe" -e john@example.com

# With Docker support
./fastapi-generator.sh -n my-api --docker

# Using custom configuration
./fastapi-generator.sh --config examples/full-stack.conf

# All options combined
./fastapi-generator.sh \
  -n my-enterprise-api \
  -d "Enterprise API with all features" \
  -a "Jane Smith" \
  -e jane@company.com \
  --docker \
  --config examples/full-stack.conf
```

## Configuration System

### Default Configuration

The `config/default.conf` file contains all default settings:

```bash
# View default configuration
cat config/default.conf
```

Key configuration sections:
- **Project defaults**: Name, description, author
- **Database settings**: Type, connection details
- **Features**: What to include/exclude
- **Dependencies**: Python packages
- **Directory structure**: Custom directories

### Pre-built Configurations

#### Minimal Configuration
```bash
./fastapi-generator.sh --config examples/minimal.conf
```
- Basic FastAPI setup
- No Docker, Redis, or advanced features
- Perfect for simple APIs

#### Full-stack Configuration
```bash
./fastapi-generator.sh --config examples/full-stack.conf
```
- All features enabled
- Docker support
- Celery, WebSockets, monitoring
- Production-ready setup

#### Microservice Configuration
```bash
./fastapi-generator.sh --config examples/microservice.conf
```
- Optimized for containerized microservices
- Health checks and metrics
- Service mesh ready

### Custom Configuration

1. **Create your own configuration:**
   ```bash
   cp config/custom.conf.example config/my-project.conf
   ```

2. **Edit the configuration:**
   ```bash
   # Edit with your preferred editor
   nano config/my-project.conf
   ```

3. **Use your configuration:**
   ```bash
   ./fastapi-generator.sh --config config/my-project.conf
   ```

## Customizing the Generator

### Adding New Features

#### 1. Create a New Generator Module

```bash
# Create new generator file
touch generators/monitoring.sh
```

```bash
# generators/monitoring.sh
#!/bin/bash

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

generate_grafana_config() {
    cat > monitoring/grafana/dashboard.json << 'EOF'
{
  "dashboard": {
    "title": "FastAPI Metrics",
    "panels": [...]
  }
}
EOF
}
```

#### 2. Update Main Generator

Add your module to `fastapi-generator.sh`:

```bash
# Add to source statements
source "$SCRIPT_DIR/generators/monitoring.sh"

# Add to generation process
if [[ "$INCLUDE_MONITORING" == true ]]; then
    print_status "Generating monitoring configuration..."
    generate_prometheus_config
    generate_grafana_config
fi
```

#### 3. Add Configuration Options

Update `config/default.conf`:

```bash
# Monitoring features
INCLUDE_MONITORING=false
MONITORING_TYPE="prometheus"  # or "datadog", "newrelic"

# Monitoring dependencies
MONITORING_REQUIREMENTS=(
    "prometheus-client==0.17.1"
    "grafana-api==1.0.3"
)
```

### Modifying Existing Templates

#### 1. Edit Generator Files

Example: Adding new fields to user model

```bash
# Edit generators/models.sh
nano generators/models.sh
```

```bash
# In generate_user_models function, add:
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    last_login: Optional[datetime] = None
```

#### 2. Update Related Files

Don't forget to update:
- Schemas (`generators/api.sh` - `generate_user_schemas`)
- Repository methods
- API endpoints
- Tests

### Creating Templates

#### 1. Template Directory Structure

```bash
mkdir -p templates/custom/api/endpoints
mkdir -p templates/custom/models
mkdir -p templates/custom/services
```

#### 2. Template Files

Create template files with placeholders:

```python
# templates/custom/models/product.py.template
"""Product model."""

from typing import Optional, List
from sqlmodel import Field, SQLModel, Relationship
from decimal import Decimal

from .base import BaseModel


class Product(BaseModel, SQLModel, table=True):
    """Product model."""
    
    __tablename__ = "products"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    description: Optional[str] = None
    price: Decimal = Field(decimal_places=2)
    sku: str = Field(unique=True, index=True)
    category_id: Optional[int] = Field(foreign_key="categories.id")
    is_active: bool = Field(default=True)
    
    # Relationships
    category: Optional["Category"] = Relationship(back_populates="products")
```

#### 3. Template Processing

Add template processing to your generator:

```bash
# In generators/models.sh
generate_from_template() {
    local template_file="$1"
    local output_file="$2"
    
    if [[ -f "$template_file" ]]; then
        # Process template with variable substitution
        envsubst < "$template_file" > "$output_file"
        print_success "Generated $output_file from template"
    fi
}
```

## Advanced Features

### Environment-specific Generation

#### 1. Environment Configurations

```bash
# config/environments/development.conf
DEBUG=true
DATABASE_URL="postgresql://user:pass@localhost/dev_db"
LOG_LEVEL="DEBUG"

# config/environments/production.conf
DEBUG=false
DATABASE_URL="postgresql://user:pass@prod-db/prod_db"
LOG_LEVEL="INFO"
```

#### 2. Multi-environment Generation

```bash
# Generate for specific environment
./fastapi-generator.sh --config config/environments/production.conf
```

### Plugin System

#### 1. Create Plugin Structure

```bash
mkdir -p plugins/auth-providers
mkdir -p plugins/databases
mkdir -p plugins/storage
```

#### 2. Plugin Example

```bash
# plugins/auth-providers/oauth.sh
#!/bin/bash

generate_oauth_config() {
    cat > src/auth/oauth.py << 'EOF'
"""OAuth authentication providers."""

from authlib.integrations.starlette_client import OAuth
from src.core.config import settings

oauth = OAuth()

# Google OAuth
oauth.register(
    name='google',
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid_configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# GitHub OAuth
oauth.register(
    name='github',
    client_id=settings.GITHUB_CLIENT_ID,
    client_secret=settings.GITHUB_CLIENT_SECRET,
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)
EOF
}

add_oauth_dependencies() {
    append_requirement "authlib==1.2.1"
    append_requirement "itsdangerous==2.1.2"
}
```

#### 3. Load Plugins

```bash
# In main generator script
load_plugins() {
    local plugin_dir="$SCRIPT_DIR/plugins"
    
    if [[ -d "$plugin_dir" ]]; then
        for plugin in "$plugin_dir"/*/*.sh; do
            if [[ -f "$plugin" ]]; then
                source "$plugin"
                print_debug "Loaded plugin: $plugin"
            fi
        done
    fi
}
```

## Testing the Generator

### Unit Testing Generator Functions

```bash
# tests/test_generator.sh
#!/bin/bash

source utils/colors.sh
source utils/helpers.sh

test_sanitize_project_name() {
    local result=$(sanitize_project_name "My Cool API!")
    local expected="my-cool-api"
    
    if [[ "$result" == "$expected" ]]; then
        print_success "✓ sanitize_project_name test passed"
    else
        print_error "✗ sanitize_project_name test failed: expected '$expected', got '$result'"
        return 1
    fi
}

test_validate_email() {
    if validate_email "test@example.com"; then
        print_success "✓ validate_email test passed"
    else
        print_error "✗ validate_email test failed"
        return 1
    fi
}

# Run tests
run_tests() {
    print_status "Running generator tests..."
    
    test_sanitize_project_name
    test_validate_email
    
    print_success "All tests passed!"
}

run_tests
```

### Integration Testing

```bash
# tests/integration_test.sh
#!/bin/bash

test_minimal_generation() {
    local test_dir="test_minimal_$(date +%s)"
    
    print_status "Testing minimal project generation..."
    
    # Generate project
    ./fastapi-generator.sh \
        -n "$test_dir" \
        -d "Test project" \
        -a "Test User" \
        -e "test@example.com" \
        --config examples/minimal.conf
    
    # Check generated files
    if [[ -f "$test_dir/main.py" ]]; then
        print_success "✓ main.py generated"
    else
        print_error "✗ main.py not found"
        return 1
    fi
    
    # Check Python syntax
    cd "$test_dir"
    python -m py_compile main.py
    if [[ $? -eq 0 ]]; then
        print_success "✓ Generated code has valid syntax"
    else
        print_error "✗ Generated code has syntax errors"
        return 1
    fi
    
    cd ..
    rm -rf "$test_dir"
    print_success "Minimal generation test passed"
}

test_docker_generation() {
    local test_dir="test_docker_$(date +%s)"
    
    print_status "Testing Docker project generation..."
    
    ./fastapi-generator.sh \
        -n "$test_dir" \
        --docker \
        --config examples/full-stack.conf
    
    # Check Docker files
    if [[ -f "$test_dir/Dockerfile" && -f "$test_dir/docker-compose.yml" ]]; then
        print_success "✓ Docker files generated"
    else
        print_error "✗ Docker files not found"
        return 1
    fi
    
    rm -rf "$test_dir"
    print_success "Docker generation test passed"
}

# Run integration tests
run_integration_tests() {
    print_status "Running integration tests..."
    
    test_minimal_generation
    test_docker_generation
    
    print_success "All integration tests passed!"
}

run_integration_tests
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied

```bash
# Problem: ./fastapi-generator.sh: Permission denied
# Solution:
chmod +x fastapi-generator.sh
chmod +x setup.sh
```

#### 2. Missing Dependencies

```bash
# Problem: Command not found errors
# Solution: Install required tools
sudo apt update
sudo apt install -y git curl wget

# For macOS:
brew install git curl wget
```

#### 3. Configuration Not Loading

```bash
# Problem: Custom configuration ignored
# Solution: Check file path and permissions
ls -la config/my-config.conf
chmod 644 config/my-config.conf

# Verify configuration syntax
bash -n config/my-config.conf
```

#### 4. Generated Code Errors

```bash
# Problem: Generated code has syntax errors
# Solution: Check template files
python -m py_compile generated-project/main.py

# Check for template variable issues
grep -r "{{" generated-project/
grep -r "}}" generated-project/
```

### Debugging the Generator

#### 1. Enable Debug Mode

```bash
# Run with debug output
DEBUG=true ./fastapi-generator.sh -n test-project
```

#### 2. Verbose Output

```bash
# Add debug prints to your generators
print_debug "Processing template: $template_file"
print_debug "Variables: PROJECT_NAME=$PROJECT_NAME"
```

#### 3. Dry Run Mode

Add dry run capability:

```bash
# In utils/helpers.sh
write_file_safe() {
    local file="$1"
    local content="$2"
    
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        print_debug "DRY RUN: Would write to $file"
        print_debug "Content preview: $(echo "$content" | head -3)"
    else
        echo "$content" > "$file"
    fi
}

# Usage:
DRY_RUN=true ./fastapi-generator.sh -n test-project
```

### Validation and Quality Checks

#### 1. Code Quality Validation

```bash
# Add to generator
validate_generated_code() {
    local project_dir="$1"
    
    cd "$project_dir"
    
    # Check Python syntax
    find . -name "*.py" -exec python -m py_compile {} \;
    
    # Check imports
    python -c "import main; print('✓ Main module imports successfully')"
    
    # Check requirements
    pip check
    
    cd ..
}
```

#### 2. Project Structure Validation

```bash
validate_project_structure() {
    local project_dir="$1"
    local required_files=(
        "main.py"
        "requirements.txt"
        ".env"
        "src/__init__.py"
        "src/core/config.py"
        "src/api/router.py"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$project_dir/$file" ]]; then
            print_error "Required file missing: $file"
            return 1
        fi
    done
    
    print_success "Project structure validation passed"
}
```

## Best Practices

### Generator Development

1. **Modular Design**: Keep generators focused and single-purpose
2. **Error Handling**: Add proper error checking and recovery
3. **Logging**: Use consistent logging throughout
4. **Testing**: Test generated code automatically
5. **Documentation**: Document all configuration options

### Configuration Management

1. **Environment Separation**: Use different configs for different environments
2. **Validation**: Validate configuration before generation
3. **Defaults**: Provide sensible defaults for all options
4. **Documentation**: Document all configuration options

### Code Generation

1. **Templates**: Use templates for complex code generation
2. **Consistency**: Maintain consistent code style
3. **Comments**: Add helpful comments to generated code
4. **Error Handling**: Include proper error handling in generated code

This usage guide provides comprehensive information for using and customizing the modular FastAPI generator. The modular design makes it easy to extend and adapt to your specific needs.