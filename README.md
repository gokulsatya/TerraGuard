# TerraGuard: Security Validation for Terraform Configurations

TerraGuard is a Python-based security validation tool that helps developers identify potential security issues in their Terraform configurations before deployment. Think of it as a friendly security guard that reads through your Terraform files and points out potential security problems before they become real issues.

## Features

TerraGuard analyzes your Terraform configurations for common security issues including:

- S3 bucket misconfigurations (public access, missing encryption)
- Network security risks (open security groups, exposed ports)
- IAM security concerns (overly permissive policies, hardcoded credentials)
- Database vulnerabilities (public access, missing encryption)
- API Gateway security issues
- Container and Kubernetes security risks
- Cloud service configuration problems

The tool provides both console output with color-coded findings and detailed HTML reports with remediation suggestions.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/terraguard.git
cd terraguard
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

To scan a single Terraform file:
```bash
python src/main.py path/to/your/terraform/file.tf
```

The tool will generate:
- Console output with color-coded findings
- An HTML report in the `reports/` directory

### Example Output

Console output includes:
- Total number of findings
- Findings by severity (CRITICAL, HIGH, MEDIUM, LOW)
- Detailed description of each issue
- Suggested fixes

HTML reports provide:
- Comprehensive security analysis
- Statistics and metrics
- Detailed findings with code snippets
- Remediation recommendations

## Security Rules

TerraGuard implements various security rules across different categories:

### S3 Bucket Security
- Encryption validation
- Public access checks
- Logging configuration verification

### Network Security
- Security group analysis
- VPC configuration validation
- Port exposure detection

### IAM Security
- Policy permission analysis
- Role configuration validation
- Credential exposure checks
- Password policy verification

### Database Security
- Access control validation
- Encryption verification
- Backup configuration checks

### Container and Kubernetes Security
- ECS task definition validation
- EKS cluster security checks
- DynamoDB configuration analysis

## Testing

Run the test suite:
```bash
python -m unittest discover tests
```

## Project Structure

```
terraguard/
├── src/
│   ├── parser/          # Terraform file parsing
│   ├── rules/           # Security rule definitions
│   └── report/          # Report generation
├── tests/               # Test suite
├── examples/            # Example Terraform files
└── reports/            # Generated security reports
```

## Example Files

The `examples/` directory contains sample Terraform configurations demonstrating both secure and insecure practices:

- `api_gateway_example.tf`: API Gateway configurations
- `cloud_services_example.tf`: Various cloud service setups
- `container_db_example.tf`: Container and database configurations
- `database_example.tf`: Database configurations
- `iam_example.tf`: IAM policies and roles
- `network_example.tf`: Network security configurations
- `secure_example.tf`: Secure configuration examples
- `insecure_example.tf`: Examples of security issues

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

Please ensure your code includes appropriate tests and documentation.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

Special thanks to the security community and Terraform developers who have documented common security issues and best practices that this tool helps identify.

## Future Enhancements

While the current version is fully functional, future enhancements could include:

- Custom rule creation support
- Configuration file for rule customization
- CI/CD pipeline integration
- Real-time scanning capabilities
- Enhanced performance metrics
- Additional cloud provider support

## Contact

For bugs, feature requests, or questions, please open an issue in the GitHub repository.
