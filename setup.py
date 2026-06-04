from setuptools import find_packages
from setuptools import setup

setup(
    name="regulatory-compliance",
    version="2.0.0",
    description="Multi-framework regulatory compliance engine for US financial institutions.",
    packages=find_packages(),
    python_requires=">=3.12",
    install_requires=[
        "boto3==1.34.144",
        "anthropic==0.40.0",
        "pyyaml==6.0.2",
        "python-json-logger==2.0.7",
    ],
)
