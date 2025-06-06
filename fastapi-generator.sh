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
    AUTHOR_NAME=$(prompt_with_default "Enter author name" "${AUTHOR_NAME:-$(git config user.name 2>/dev/null || echo 'Your Name')}")
    AUTHOR_EMAIL=$(prompt_with_default "Enter author email" "${AUTHOR_EMAIL:-$(git config user.email 2>/dev/null || echo 'your.email@example.com')}")

    # Prompt user for the parent directory
    read -p "$(echo -e "${GREEN}Enter the parent directory where the project will be created (e.g., /home/user/projects, or leave blank for current directory): ${NC}")" PARENT_DIR_INPUT
    
    # Resolve the absolute path of the parent directory
    if [[ -z "$PARENT_DIR_INPUT" ]]; then
        PROJECT_PARENT_DIR="$(pwd)" # Current directory
    else
        PROJECT_PARENT_DIR="$(cd "$PARENT_DIR_INPUT" && pwd)"
        if [[ $? -ne 0 ]]; then
            print_error "Invalid directory: $PARENT_DIR_INPUT. Using current directory instead."
            PROJECT_PARENT_DIR="$(pwd)"
        fi
    fi
    echo -e "${YELLOW}Project will be created in: $PROJECT_PARENT_DIR/${PROJECT_NAME}${NC}"
    # --- END NEW ADDITION ---

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
}

# Create project structure
create_project_structure() {
   # Sanitize project name for directory
    PROJECT_DIR_NAME=$(echo "$PROJECT_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]/-/g' | sed 's/--*/-/g' | sed 's/^-\|-$//g')
    
    # Combine parent directory and project name to get the full path
    PROJECT_FULL_PATH="$PROJECT_PARENT_DIR/$PROJECT_DIR_NAME"

    print_status "Creating project directory: $PROJECT_FULL_PATH"

    # Check if directory already exists
    if [[ -d "$PROJECT_FULL_PATH" ]]; then
        print_error "Directory $PROJECT_FULL_PATH already exists!"
        exit 1
    fi

    # Create project structure
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

    print_status "Generating documentation..."
    generate_readme

    cd ..
}

# Show completion message
show_completion() {
    print_success "FastAPI JWT boilerplate created successfully!"

    echo ""
    print_status "Next steps:"
    echo "1. cd $PROJECT_DIR"

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
    print_warning "IMPORTANT: Remember to change JWT_SECRET_KEY in production!"
    print_success "Project '$PROJECT_NAME' created in directory '$PROJECT_DIR'"
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