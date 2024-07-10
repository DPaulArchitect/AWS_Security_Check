from setuptools import setup, find_packages

setup(
    name='aws_security_checker_app',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'boto3',
        'tk',
    ],
    entry_points={
        'console_scripts': [
            'aws_security_checker=app:main',
        ],
    },
    author='David Paul',
    description='A GUI tool for auditing AWS S3 bucket security.',
)
