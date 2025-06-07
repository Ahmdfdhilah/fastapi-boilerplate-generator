#!/bin/bash

# FastAPI JWT Boilerplate Generator - Main Script
# Modular version for easy customization and maintenance

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source configuration and utility files
source "$SCRIPT_DIR/config/default.conf"
source "$SCRIPT_DIR/utils/colors.sh"
source "$SCRIPT_DIR/utils/helpers.sh"
source "$SCRIPT_DIR/generators/core.sh"
source "$SCRIPT_DIR/generators/auth.sh"
source "$SCRIPT_DIR/generators/models.sh"
source "$SCRIPT_DIR/generators/api.sh"
source "$SCRIPT_DIR/generators/middleware.sh"
source "$SCRIPT_DIR/generators/utils.sh"
source "$SCRIPT_DIR/generators/tests.sh"
source "$SCRIPT_DIR/generators/docker.sh"
source "$SCRIPT_DIR/generators/docs.sh"
source "$SCRIPT_DIR/generators/redis.sh"

# Function to show usage
show_usage() {
    echo -e "${BLUE}FastAPI JWT Boilerplate Generator${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -n, --name NAME           Project name (default: my-fastapi-service)"
    echo "  -d, --description DESC    Project description"
    echo "  -a, --author AUTHOR       Author name"
    echo "  -e, --email EMAIL         Author email"
    echo "  --docker                  Include Docker configuration"
    echo "  --no-docker               Skip Docker configuration (default)"
    echo "  --config FILE             Use custom configuration file"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -n my-api -a \"John Doe\" -e john@example.com --docker"
    echo "  $0 --config custom.conf"
    echo ""
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--name)
                PROJECT_NAME="$2"
                shift 2
                ;;
            -d|--description)
                PROJECT_DESCRIPTION="$2"
                shift 2
                ;;
            -a|--author)
                AUTHOR_NAME="$2"
                shift 2
                ;;
            -e|--email)
                AUTHOR_EMAIL="$2"
                shift 2
                ;;
            --docker)
                USE_DOCKER=true
                shift
                ;;
            --no-docker)
                USE_DOCKER=false
                shift
                ;;
            --config)
                CUSTOM_CONFIG="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Load custom configuration if provided
load_custom_config() {
    if [[ -n "$CUSTOM_CONFIG" && -f "$CUSTOM_CONFIG" ]]; then
        print_status "Loading custom configuration: $CUSTOM_CONFIG"
        source "$CUSTOM_CONFIG"
    fi
}

# Interactive mode for gathering project details
interactive_setup() {
    echo -e "${BLUE}=== FastAPI JWT Boilerplate Generator ===${NC}"
    echo ""

    PROJECT_NAME=$(prompt_with_default "Enter project name" "${PROJECT_NAME:-my-fastapi-service}")
    PROJECT_DESCRIPTION=$(prompt_with_default "Enter project description" "${PROJECT_DESCRIPTION:-FastAPI service with JWT authentication}")
    AUTHOR_NAME=$(prompt_with_default "Enter author name" "${AUTHOR_NAME:-$(get_git_user_name)}")
    AUTHOR_EMAIL=$(prompt_with_default "Enter author email" "${AUTHOR_EMAIL:-$(get_git_user_email)}")

    # Prompt user for the parent directory
    read -p "$(echo -e "${GREEN}Enter the parent directory where the project will be created (leave blank for parent directory): ${NC}")" PARENT_DIR_INPUT
    
    # Resolve the absolute path of the parent directory
    if [[ -z "$PARENT_DIR_INPUT" ]]; then
        # If empty, go one level up from script directory
        SCRIPT_PARENT_DIR="$(dirname "$SCRIPT_DIR")"
        if [[ -d "$SCRIPT_PARENT_DIR" && -w "$SCRIPT_PARENT_DIR" ]]; then
            PROJECT_PARENT_DIR="$(cd "$SCRIPT_PARENT_DIR" && pwd)"
            print_status "Using parent directory (one level up from script location)"
        else
            print_warning "Cannot access parent directory, using current working directory instead"
            PROJECT_PARENT_DIR="$(pwd)"
        fi
    else
        # Expand tilde and resolve absolute path
        PARENT_DIR_INPUT="${PARENT_DIR_INPUT/#\~/$HOME}"
        
        if [[ -d "$PARENT_DIR_INPUT" && -w "$PARENT_DIR_INPUT" ]]; then
            PROJECT_PARENT_DIR="$(cd "$PARENT_DIR_INPUT" && pwd)"
        else
            print_error "Invalid or inaccessible directory: $PARENT_DIR_INPUT"
            SCRIPT_PARENT_DIR="$(dirname "$SCRIPT_DIR")"
            if [[ -d "$SCRIPT_PARENT_DIR" && -w "$SCRIPT_PARENT_DIR" ]]; then
                PROJECT_PARENT_DIR="$(cd "$SCRIPT_PARENT_DIR" && pwd)"
                print_status "Using parent directory instead"
            else
                PROJECT_PARENT_DIR="$(pwd)"
                print_warning "Using current working directory instead"
            fi
        fi
    fi

    # Ask for deployment preference if not set
    if [[ -z "$USE_DOCKER" ]]; then
        echo ""
        print_status "Choose deployment method:"
        echo "1. Plain uvicorn (no Docker)"
        echo "2. Docker with docker-compose"
        echo ""
        DEPLOYMENT_CHOICE=$(prompt_with_default "Enter your choice (1 or 2)" "1")

        case $DEPLOYMENT_CHOICE in
            1)
                USE_DOCKER=false
                print_status "Selected: Plain uvicorn deployment"
                ;;
            2)
                USE_DOCKER=true
                print_status "Selected: Docker deployment with docker-compose"
                ;;
            *)
                USE_DOCKER=false
                print_warning "Invalid choice, defaulting to plain uvicorn"
                ;;
        esac
    fi

    # Redis Configuration Choice
    echo ""
    print_status "Redis Configuration:"
    echo "Redis provides token blacklist functionality and caching capabilities."
    echo "Without Redis, tokens cannot be revoked until they expire naturally."
    echo ""
    echo "1. Enable Redis (Recommended for production)"
    echo "2. Skip Redis (Basic JWT only)"
    echo ""
    REDIS_CHOICE=$(prompt_with_default "Enter your choice (1 or 2)" "1")

    case $REDIS_CHOICE in
        1)
            REDIS_ENABLED=true
            print_success "Redis enabled - Token revocation and caching available"
            ;;
        2)
            REDIS_ENABLED=false
            print_warning "Redis disabled - Tokens cannot be revoked before expiry"
            ;;
        *)
            REDIS_ENABLED=true
            print_warning "Invalid choice, defaulting to Redis enabled"
            ;;
    esac
}

# Validate project configuration
validate_config() {
    if [[ -z "$PROJECT_NAME" ]]; then
        print_error "Project name is required"
        exit 1
    fi

    if [[ ! "$PROJECT_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_error "Project name can only contain letters, numbers, hyphens, and underscores"
        exit 1
    fi

    # Validate email if provided
    if [[ -n "$AUTHOR_EMAIL" ]] && ! validate_email "$AUTHOR_EMAIL"; then
        print_warning "Invalid email format: $AUTHOR_EMAIL"
    fi
}

# Create project structure
create_project_structure() {
    # Sanitize project name for directory
    PROJECT_DIR_NAME=$(sanitize_project_name "$PROJECT_NAME")
    
    # Combine parent directory and project name to get the full path
    PROJECT_FULL_PATH="$PROJECT_PARENT_DIR/$PROJECT_DIR_NAME"

    print_status "Creating project directory: $PROJECT_FULL_PATH"

    # Check if directory already exists
    if [[ -d "$PROJECT_FULL_PATH" ]]; then
        print_error "Directory $PROJECT_FULL_PATH already exists!"
        if confirm "Do you want to continue and overwrite existing files?"; then
            print_warning "Continuing with existing directory..."
        else
            print_status "Operation cancelled."
            exit 1
        fi
    fi

    # Create and enter project directory
    mkdir -p "$PROJECT_FULL_PATH"
    cd "$PROJECT_FULL_PATH"

    print_status "Creating project structure..."

    # Create directory structure
    create_directories

    print_status "Generating configuration files..."
    generate_env_file
    generate_requirements
    generate_gitignore

    print_status "Generating core files..."
    generate_core_config
    generate_database_config

    print_status "Generating authentication system..."
    generate_auth_jwt
    generate_auth_permissions

    print_status "Generating models..."
    generate_base_models
    generate_user_models

    print_status "Generating schemas..."
    generate_user_schemas
    generate_common_schemas

    print_status "Generating repositories..."
    generate_user_repository

    print_status "Generating services..."
    generate_user_service
    generate_auth_service

    print_status "Generating API endpoints..."
    generate_auth_endpoints
    generate_user_endpoints
    generate_api_router

    print_status "Generating middleware..."
    generate_error_handler
    generate_logging_middleware

    print_status "Generating utilities..."
    generate_logging_utils
    generate_validators

    print_status "Generating main application..."
    generate_main_app

    print_status "Generating database migrations..."
    generate_alembic_config

    print_status "Generating tests..."
    generate_test_config
    generate_auth_tests

    if [[ "$USE_DOCKER" == true ]]; then
        print_status "Generating Docker configuration..."
        generate_dockerfile
        generate_docker_compose
        generate_dockerignore
    fi

    if [[ "$REDIS_ENABLED" == true ]]; then
        print_status "Generating Redis integration..."
        generate_redis_integration
    else
        print_status "Skipping Redis integration (disabled)"
    fi

    print_status "Generating documentation..."
    generate_readme

    # Initialize git repository if git is available
    if command_exists git && ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_status "Initializing git repository..."
        git init
        git add .
        git commit -m "Initial commit: FastAPI boilerplate generated"
    fi
}

# Show completion message
show_completion() {
    print_success "FastAPI JWT boilerplate created successfully!"

    echo ""
    print_header "🎉 Project Created: $PROJECT_NAME"
    echo -e "${CYAN}Location: $PROJECT_FULL_PATH${NC}"
    echo ""

    print_status "Next steps:"
    echo "1. cd $PROJECT_DIR_NAME"

    if [[ "$USE_DOCKER" == true ]]; then
        echo "2. Edit .env file with your database settings (if needed)"
        echo "3. docker-compose up --build"
        echo ""
        print_status "Your FastAPI service will be available at:"
        echo "- API: http://localhost:8000"
        echo "- Docs: http://localhost:8000/docs"
        echo "- ReDoc: http://localhost:8000/redoc"
        echo "- PostgreSQL: localhost:5432"
        echo "- Redis: localhost:6379"
        echo ""
        print_status "Docker services included:"
        echo "- FastAPI application"
        echo "- PostgreSQL database"
        echo "- Redis cache"
    else
        echo "2. python -m venv venv"
        echo "3. source venv/bin/activate  # On Windows: venv\\Scripts\\activate"
        echo "4. pip install -r requirements.txt"
        echo "5. Edit .env file with your database settings"
        echo "6. alembic revision --autogenerate -m \"Initial migration\""
        echo "7. alembic upgrade head"
        echo "8. python main.py"
        echo ""
        print_status "Your FastAPI service will be available at:"
        echo "- API: http://localhost:8000"
        echo "- Docs: http://localhost:8000/docs"
        echo "- ReDoc: http://localhost:8000/redoc"
        echo ""
        print_status "Manual setup required:"
        echo "- PostgreSQL database server"
        echo "- Redis server (optional)"
    fi

    echo ""
    print_status "API Endpoints:"
    echo "- POST /api/v1/auth/register - Register new user"
    echo "- POST /api/v1/auth/login    - Login user"
    echo "- GET  /api/v1/users/me      - Get current user (authenticated)"
    echo "- PUT  /api/v1/users/me      - Update current user (authenticated)"

    echo ""
    print_warning "IMPORTANT SECURITY NOTES:"
    echo "- Change JWT_SECRET_KEY in production!"
    echo "- Configure CORS_ORIGINS for your domain"
    echo "- Use HTTPS in production"
    echo "- Review and strengthen password policies"

    echo ""
    print_success "🚀 Project '$PROJECT_NAME' ready for development!"
    print_status "Generated in: $PROJECT_FULL_PATH"
}

# Main execution
main() {
    # Parse command line arguments
    parse_arguments "$@"
    
    # Load custom configuration if provided
    load_custom_config
    
    # If no arguments provided or project name is not set, run interactive mode
    if [[ $# -eq 0 || -z "$PROJECT_NAME" ]]; then
        interactive_setup
    fi
    
    # Validate configuration
    validate_config
    
    # Create project
    create_project_structure
    
    # Show completion message
    show_completion
}

# Run main function with all arguments
main "$@"