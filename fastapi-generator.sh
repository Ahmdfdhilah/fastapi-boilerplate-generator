#!/bin/bash

# FastAPI JWT Boilerplate Generator - Complete Main Script with Step 1
# Password Security Standards Implementation

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
    echo -e "${BLUE}FastAPI JWT Boilerplate Generator with Password Security${NC}"
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
    echo "Features included:"
    echo "  ✓ STEP 1: Password Security Standards (OWASP compliant)"
    echo "  ✓ Strong password validation (12+ chars, complexity)"
    echo "  ✓ Password history tracking (prevent reuse of last 5)"
    echo "  ✓ Account lockout protection (5 failed attempts)"
    echo "  ✓ Common password blacklist"
    echo "  ✓ Password strength scoring and feedback"
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
    echo -e "${BLUE}=== FastAPI JWT Boilerplate Generator (with Password Security) ===${NC}"
    echo ""

    PROJECT_NAME=$(prompt_with_default "Enter project name" "${PROJECT_NAME:-my-fastapi-service}")
    PROJECT_DESCRIPTION=$(prompt_with_default "Enter project description" "${PROJECT_DESCRIPTION:-FastAPI service with JWT authentication and password security}")
    AUTHOR_NAME=$(prompt_with_default "Enter author name" "${AUTHOR_NAME:-$(get_git_user_name)}")
    AUTHOR_EMAIL=$(prompt_with_default "Enter author email" "${AUTHOR_EMAIL:-$(get_git_user_email)}")

    # Prompt user for the parent directory
    read -p "$(echo -e "${GREEN}Enter the parent directory where the project will be created (or leave blank for parent directory): ${NC}")" PARENT_DIR_INPUT
    
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
    echo -e "${YELLOW}Project will be created in: $PROJECT_PARENT_DIR/${PROJECT_NAME}${NC}"

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
    if [[ -n "$AUTHOR_EMAIL" ]]; then
        if ! [[ "$AUTHOR_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            print_warning "Author email format may be invalid"
        fi
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
        if confirm "Do you want to remove the existing directory and continue?"; then
            rm -rf "$PROJECT_FULL_PATH"
            print_status "Removed existing directory"
        else
            exit 1
        fi
    fi

    # Create project structure
    mkdir -p "$PROJECT_FULL_PATH"
    cd "$PROJECT_FULL_PATH"

    # Set PROJECT_DIR for use in generators
    PROJECT_DIR="$PROJECT_DIR_NAME"

    print_header "Creating FastAPI Project with Password Security"

    print_step "Creating project structure..."
    create_directories

    print_step "Generating configuration files..."
    generate_env_file
    generate_requirements
    generate_gitignore

    print_step "Generating core files..."
    generate_core_config
    generate_database_config

    print_step "Generating authentication system..."
    generate_auth_jwt
    generate_auth_permissions

    print_step "Generating models with password security..."
    generate_base_models
    generate_user_models

    print_step "Generating schemas with password validation..."
    generate_user_schemas
    generate_common_schemas

    print_step "Generating repositories..."
    generate_user_repository

    print_step "Generating services with password security..."
    generate_user_service
    generate_auth_service

    print_step "Generating API endpoints..."
    generate_auth_endpoints
    generate_user_endpoints
    generate_api_router

    print_step "Generating middleware..."
    generate_error_handler
    generate_logging_middleware

    print_step "Generating utilities with password validation..."
    generate_validators
    generate_logging_utils
    generate_password_utils

    print_step "Generating Redis utilities..."
    generate_redis_connection
    generate_redis_cache
    generate_redis_sessions
    generate_redis_rate_limiting
    generate_redis_middleware

    print_step "Generating main application..."
    generate_main_app

    print_step "Generating database migrations..."
    generate_alembic_config

    print_step "Generating comprehensive tests..."
    generate_test_config
    generate_auth_tests
    generate_password_tests

    if [[ "$USE_DOCKER" == true ]]; then
        print_step "Generating Docker configuration..."
        generate_dockerfile
        generate_docker_compose
        generate_dockerignore
    fi

    print_step "Generating documentation..."
    generate_readme

    cd ..
}

# Show completion message with Step 1 features
show_completion() {
    print_success "FastAPI JWT boilerplate with Password Security created successfully!"

    echo ""
    print_header "STEP 1: Password Security Standards - IMPLEMENTED ✓"
    echo -e "${GREEN}✓ OWASP-compliant password validation${NC}"
    echo -e "${GREEN}✓ Strong password requirements (12+ chars, complexity)${NC}"
    echo -e "${GREEN}✓ Password history tracking (prevents reuse of last 5)${NC}"
    echo -e "${GREEN}✓ Account lockout protection (5 failed attempts)${NC}"
    echo -e "${GREEN}✓ Common password blacklist (50+ passwords)${NC}"
    echo -e "${GREEN}✓ Password strength scoring (0-100)${NC}"
    echo -e "${GREEN}✓ Real-time password strength feedback${NC}"
    echo -e "${GREEN}✓ Secure password reset with tokens${NC}"
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
        echo "- FastAPI application with password security"
        echo "- PostgreSQL database"
        echo "- Redis cache"
    else
        echo "2. python -m venv venv"
        echo "3. source venv/bin/activate  # On Windows: venv\\Scripts\\activate"
        echo "4. pip install -r requirements.txt"
        echo "5. Edit .env file with your database settings"
        echo "6. alembic revision --autogenerate -m \"Initial migration with password security\""
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
    print_status "API Endpoints with Password Security:"
    echo "- POST /api/v1/auth/register           - Register with strong password validation"
    echo "- POST /api/v1/auth/login              - Login with lockout protection"
    echo "- POST /api/v1/auth/change-password    - Change password with history check"
    echo "- POST /api/v1/auth/check-password-strength - Real-time password validation"
    echo "- POST /api/v1/auth/request-password-reset  - Request password reset token"
    echo "- POST /api/v1/auth/confirm-password-reset  - Reset password with token"
    echo "- GET  /api/v1/users/me                - Get current user info"
    echo ""

    print_status "Testing your implementation:"
    echo "- Run tests: pytest"
    echo "- Test password validation: pytest tests/test_password_validation.py"
    echo "- Test auth endpoints: pytest tests/test_auth.py"
    echo ""

    print_warning "IMPORTANT SECURITY NOTES:"
    echo "🔒 Change JWT_SECRET_KEY in production!"
    echo "🔒 Review and adjust password policies in .env"
    echo "🔒 Configure proper CORS origins for production"
    echo "🔒 Set up email service for password reset (Step 5)"
    echo ""

    print_status "Password Security Configuration (in .env):"
    echo "- PASSWORD_MIN_LENGTH=12              # Minimum password length"
    echo "- PASSWORD_MAX_LENGTH=128             # Maximum password length"
    echo "- PASSWORD_HISTORY_COUNT=5            # Number of old passwords to remember"
    echo "- PASSWORD_MAX_AGE_DAYS=90            # Password expiry (future feature)"
    echo "- ACCOUNT_LOCKOUT_ATTEMPTS=5          # Failed attempts before lockout"
    echo "- ACCOUNT_LOCKOUT_DURATION_MINUTES=15 # Lockout duration"
    echo ""

    print_success "Ready for STEP 2: Account Security & Rate Limiting"
    echo "Next implementation will add:"
    echo "- Progressive lockout (increasing duration)"
    echo "- Rate limiting per IP address"
    echo "- CAPTCHA integration after failed attempts"
    echo "- Suspicious activity detection"
    echo ""

    print_success "Project '$PROJECT_NAME' created successfully in '$PROJECT_DIR_NAME'"
}

# Check prerequisites
check_prerequisites() {
    # Check if required commands exist
    local missing_commands=()
    
    if ! command_exists git; then
        missing_commands+=("git")
    fi
    
    if [[ ${#missing_commands[@]} -gt 0 ]]; then
        print_error "Missing required commands: ${missing_commands[*]}"
        print_status "Please install the missing commands and try again"
        exit 1
    fi

}


# Main execution
main() {
    # Check prerequisites
    check_prerequisites
    
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
    
    # Create project with Step 1 implementation
    create_project_structure
    
    # Generate seed data for development
    cd "$PROJECT_FULL_PATH"
    cd ..
    
    # Show completion message with Step 1 features
    show_completion
    
    print_status "Development utilities created:"
    echo "- scripts/seed_data.py - Creates admin user and default roles"
    echo "  Usage: cd $PROJECT_DIR_NAME && python scripts/seed_data.py"
    echo ""
}

# Handle script interruption
trap 'print_error "Script interrupted. Cleaning up..."; exit 1' INT TERM

# Run main function with all arguments
main "$@"