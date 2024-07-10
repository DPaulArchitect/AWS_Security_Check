from setuptools import setup, find_packages

setup(
    name='aws_security_checker',
    version='0.2.0',
    packages=find_packages(),
    install_requires=[
        'boto3',
    ],
    entry_points={
        'console_scripts': [
            'aws_security_checker=app:main',
        ],
    },
    author='David Paul',
    description='A tool for auditing AWS security configurations.',
)
