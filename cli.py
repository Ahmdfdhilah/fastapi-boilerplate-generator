"""Command Line Interface for FastAPI Boilerplate Generator."""

import click
import os
import sys
from pathlib import Path
from typing import Optional

from .core.generator import ProjectGenerator
from .core.config import load_config, list_available_configs
from .utils.file_utils import validate_project_name, validate_email


@click.command()
@click.argument('project_name', required=False)
@click.option('--author', '-a', help='Project author name')
@click.option('--email', '-e', help='Author email address')
@click.option('--description', '-d', help='Project description')
@click.option('--config', '-c', help='Configuration preset (minimal, full-stack, microservice)')
@click.option('--docker/--no-docker', default=False, help='Include Docker configuration')
@click.option('--interactive', '-i', is_flag=True, help='Interactive mode')
@click.option('--list-configs', is_flag=True, help='List available configurations')
@click.option('--output-dir', '-o', help='Output directory (default: current directory)')
@click.option('--force', is_flag=True, help='Overwrite existing directory')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.version_option(version='1.0.0', prog_name='FastAPI Generator')
def main(
    project_name: Optional[str],
    author: Optional[str],
    email: Optional[str],
    description: Optional[str],
    config: Optional[str],
    docker: bool,
    interactive: bool,
    list_configs: bool,
    output_dir: Optional[str],
    force: bool,
    verbose: bool
):
    """Generate a FastAPI boilerplate project with JWT authentication.
    
    PROJECT_NAME: Name of the project to create (optional in interactive mode)
    
    Examples:
    
    \b
    # Simple usage
    fastapi-generator my-api
    
    \b
    # With options
    fastapi-generator my-api --author "John Doe" --email "john@example.com" --docker
    
    \b
    # Using configuration preset
    fastapi-generator my-api --config full-stack
    
    \b
    # Interactive mode
    fastapi-generator --interactive
    """
    
    if list_configs:
        click.echo("Available configurations:")
        configs = list_available_configs()
        for name, description in configs.items():
            click.echo(f"  {name:<15} - {description}")
        return
    
    if interactive:
        project_name, author, email, description, config, docker = interactive_setup()
    
    if not project_name:
        click.echo("Error: Project name is required")
        click.echo("Use --interactive for guided setup or provide PROJECT_NAME argument")
        sys.exit(1)
    
    # Validate inputs
    if not validate_project_name(project_name):
        click.echo(f"Error: Invalid project name '{project_name}'")
        click.echo("Project name must contain only letters, numbers, hyphens, and underscores")
        sys.exit(1)
    
    if email and not validate_email(email):
        click.echo(f"Error: Invalid email address '{email}'")
        sys.exit(1)
    
    # Set output directory
    if output_dir:
        output_path = Path(output_dir)
    else:
        output_path = Path.cwd()
    
    project_path = output_path / project_name
    
    # Check if project directory exists
    if project_path.exists() and not force:
        click.echo(f"Error: Directory '{project_path}' already exists")
        click.echo("Use --force to overwrite")
        sys.exit(1)
    
    # Load configuration
    try:
        generator_config = load_config(config)
    except FileNotFoundError:
        click.echo(f"Error: Configuration '{config}' not found")
        click.echo("Use --list-configs to see available configurations")
        sys.exit(1)
    
    # Override config with command line options
    if docker is not None:
        generator_config['features']['docker'] = docker
    
    # Create generator
    generator = ProjectGenerator(
        project_name=project_name,
        author=author,
        email=email,
        description=description,
        config=generator_config,
        output_path=output_path,
        verbose=verbose
    )
    
    try:
        click.echo(f"Generating FastAPI project: {project_name}")
        generator.generate()
        
        click.echo()
        click.echo(click.style("✓ Project generated successfully!", fg='green', bold=True))
        click.echo()
        click.echo("Next steps:")
        click.echo(f"  cd {project_name}")
        
        if generator_config.get('features', {}).get('docker', False):
            click.echo("  docker-compose up --build")
        else:
            click.echo("  python -m venv venv")
            click.echo("  source venv/bin/activate  # On Windows: venv\\Scripts\\activate")
            click.echo("  pip install -r requirements.txt")
            click.echo("  alembic upgrade head")
            click.echo("  python main.py")
        
        click.echo()
        click.echo("Your API will be available at:")
        click.echo("  • API: http://localhost:8000")
        click.echo("  • Docs: http://localhost:8000/docs")
        click.echo("  • ReDoc: http://localhost:8000/redoc")
        
    except Exception as e:
        click.echo(f"Error generating project: {e}")
        if verbose:
            raise
        sys.exit(1)


def interactive_setup():
    """Interactive setup mode."""
    click.echo(click.style("=== FastAPI Boilerplate Generator ===", fg='blue', bold=True))
    click.echo()
    
    # Project name
    project_name = click.prompt(
        "Project name", 
        type=str,
        value_proc=lambda x: validate_project_name(x) and x or None
    )
    
    # Author
    author = click.prompt("Author name", default="", show_default=False)
    if not author:
        author = None
    
    # Email
    while True:
        email = click.prompt("Email address", default="", show_default=False)
        if not email:
            email = None
            break
        if validate_email(email):
            break
        click.echo("Invalid email format, please try again")
    
    # Description
    description = click.prompt(
        "Project description", 
        default=f"{project_name} - FastAPI service with JWT authentication"
    )
    
    # Configuration
    click.echo()
    click.echo("Available configurations:")
    configs = list_available_configs()
    for i, (name, desc) in enumerate(configs.items(), 1):
        click.echo(f"  {i}. {name} - {desc}")
    
    while True:
        choice = click.prompt(
            "Choose configuration", 
            type=click.IntRange(1, len(configs)),
            default=1
        )
        config = list(configs.keys())[choice - 1]
        break
    
    # Docker
    docker = click.confirm("Include Docker configuration?", default=False)
    
    click.echo()
    click.echo("Configuration summary:")
    click.echo(f"  Project: {project_name}")
    click.echo(f"  Author: {author or 'Not specified'}")
    click.echo(f"  Email: {email or 'Not specified'}")
    click.echo(f"  Description: {description}")
    click.echo(f"  Config: {config}")
    click.echo(f"  Docker: {'Yes' if docker else 'No'}")
    click.echo()
    
    if not click.confirm("Proceed with generation?"):
        click.echo("Aborted.")
        sys.exit(0)
    
    return project_name, author, email, description, config, docker


if __name__ == '__main__':
    main()