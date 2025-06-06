# setup.py - untuk membuat package yang bisa diinstall
from setuptools import setup, find_packages
import os

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="fastapi-boilerplate-generator",
    version="1.0.0",
    author="Ahmad Fadillah",
    author_email="fadillahbringin@gmail.com",
    description="A modular FastAPI boilerplate generator with JWT authentication",
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    url="https://github.com/ahmdfdhilah/fastapi-boilerplate-generator",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Code Generators",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "jinja2>=3.0.0",
        "pyyaml>=6.0",
        "requests>=2.25.0",
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.900",
        ],
    },
    entry_points={
        "console_scripts": [
            "fastapi-generator=fastapi_generator.cli:main",
            "fastapi-gen=fastapi_generator.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "fastapi_generator": [
            "templates/**/*",
            "configs/**/*",
            "examples/**/*",
        ],
    },
    zip_safe=False,
)