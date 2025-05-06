import os
from setuptools import find_packages, setup

version_string = os.environ.get("ARTIFACT_VERSION", "0.0.0.dev0")

setup(
    name="sto-ecs-client",
    description="ECS client.",
    author="STO",
    packages=find_packages("src"),
    version=version_string,
    package_dir={"": "src"},
    entry_points={"console_scripts": [
        "sto-ecs-client=ecs_client.commands:run"
    ]},
    install_requires=[
        "PyYAML==6.0.1",
        "requests==2.32.3",
        "setuptools==70.1.1",
        "fire==0.6.0",
        "paramiko==3.4.0",
    ],
    setup_requires=[
        "black==24.4.2",
        "flake8==7.1.0",
        "isort==5.13.2",
        "pre-commit==3.7.1",
        "pytest==8.2.2",
    ],
    tests_require=[
        "coverage==7.5.4",
        "deepdiff==7.0.1",
        "requests-mock==1.12.1",
    ],
    test_suite="tests",
)
