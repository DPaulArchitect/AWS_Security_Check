# AWS Security Checker Application

This application allows you to audit AWS S3 bucket security using a graphical user interface (GUI).

## Features

- Identifies publicly accessible S3 buckets.
- Provides recommendations for securing buckets.
- Connects to your AWS account using provided credentials.
  ADDED NEW FUNCTIONALITY V:2 BELOW
- Checks for IAM users without MFA enabled.
- Checks for overly permissive EC2 security groups.
- Checks for public access to RDS instances

## Installation

1. Clone the repository.
2. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```
3. Run the application:
    ```sh
    python app.py
    ```

## Usage

1. Enter your AWS Access Key, Secret Key, and Region.
2. Click "Connect" to start the audit.
3. View the report in the application window.

## Requirements

- Python 3.6+
- Boto3
- Tkinter
