# CryptoPIX Bridge

A comprehensive database management tool that provides secure encryption capabilities and SQL translation features. CryptoPIX Bridge serves as a transparent bridge between applications and databases, offering seamless encryption/decryption of sensitive data while maintaining full SQL compatibility.

## Features

- **Database Encryption**: CLWE-based encryption for sensitive data columns with configurable security levels
- **Multi-Database Support**: Full support for MySQL, PostgreSQL, SQLite, MSSQL, Oracle, and MongoDB
- **Virtual Database Server (VDS)**: Transparent proxy server that handles encryption/decryption on-the-fly
- **AI-Powered SQL Assistant**: Intelligent query suggestions, explanations, and natural language to SQL conversion
- **Interactive Query Console**: Web-based SQL console with AI-powered features and real-time execution
- **Database Migration Tools**: Automated migration of existing databases to encrypted format
- **Password Rotation**: Secure encryption password change functionality with data re-encryption
- **System Monitoring**: Real-time system health monitoring, logging, and analytics
- **Multi-Database Management**: Registry and management of multiple encrypted databases
- **Web-Based Interface**: Modern Flask web application for complete database management
- **Authentication & Licensing**: Secure license-based authentication system
- **Schema Management**: Automatic encrypted schema generation and management
- **Data Translation**: Advanced SQL query translation for encrypted databases
- **Backup & Recovery**: Comprehensive migration state management and recovery capabilities

## Documentation

Comprehensive documentation is available in the [docs/](docs/) folder:

- [Installation Guide](docs/installation-guide.md) - Detailed setup instructions
- [User Guide](docs/user-guide.md) - Complete usage guide
- [API Documentation](docs/api-documentation.md) - REST API reference
- [Architecture Overview](docs/architecture-overview.md) - System design and diagrams
- [Developer Guide](docs/developer-guide.md) - For contributors and developers
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions

## Installation

### Prerequisites

- Python 3.8 or higher
- Database servers (MySQL, PostgreSQL, SQLite, MSSQL, Oracle, or MongoDB)
- Valid license key for authentication

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cryptopix-dev/Cryptopix-Bridge.git
   cd Cryptopix-Bridge
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables:**
   Create a `.env` file in the root directory with the following variables:
   ```env
   CRYPTOPIX_DEFAULT_PASSWORD=your_secure_password_here
   LICENSE_SERVER_URL=https://your-license-server.com/api/bridge
   APP_HOST=0.0.0.0
   APP_PORT=8000
   DEBUG=False
   SECRET_KEY=your_secret_key_here
   ```

4. **Run the application:**
   ```bash
   python run.py
   ```

The application will be available at `http://localhost:8000`.

## Usage

### Initial Setup

1. **Start the Application:**
   Run `python run.py` and navigate to `http://localhost:8000` in your browser.

2. **Login:**
   Use your email and license key to authenticate with the license server.

3. **Configure Database Migration:**
   - Enter your source database URL (existing database to encrypt)
   - Enter your encrypted database URL (target database for encrypted data)
   - Set encryption password and security level

4. **Select Tables and Columns:**
   Choose which tables and columns to encrypt. The system automatically identifies sensitive data patterns.

5. **Run Migration:**
   Execute the migration process to encrypt your data and create the encrypted database.

6. **Start Virtual Database Server:**
   Launch the VDS to provide transparent access to encrypted data.

### Using the Query Console

- Access the Query Console from the main dashboard
- Write SQL queries that will be automatically translated for encrypted data
- Use AI suggestions for query completion and optimization
- Execute queries with real-time results

### Connecting External Applications

Applications can connect to the Virtual Database Server using standard database connection strings:

```
mysql://user:password@localhost:4406/your_database
```

The VDS handles all encryption/decryption transparently.

## Configuration

The application uses environment variables for configuration. Create a `.env` file with the following options:

### Core Settings
- `CRYPTOPIX_DEFAULT_PASSWORD`: Default encryption password (required)
- `SECURITY_LEVEL`: Encryption security level (Min/Medium/Max)
- `TAG_SALT`: Salt for consistent hashing

### Database URLs
- `SOURCE_DB_URL`: Source database connection URL
- `ENCRYPTED_DB_URL`: Encrypted database connection URL

### Virtual Database Server
- `VDS_HOST`: VDS bind host (default: 0.0.0.0)
- `VDS_PORT`: VDS bind port (default: 4406)
- `VDS_PROTOCOL`: Database protocol (default: mysql)
- `VDS_MAX_CONNECTIONS`: Maximum concurrent connections (default: 100)

### Application Settings
- `APP_HOST`: Flask app host (default: 0.0.0.0)
- `APP_PORT`: Flask app port (default: 8000)
- `DEBUG`: Enable debug mode (default: False)
- `SECRET_KEY`: Flask session secret key

### Authentication
- `LICENSE_SERVER_URL`: License server API endpoint

### MongoDB (Optional)
- `MONGODB_DATABASE`: MongoDB database name

## API Endpoints

The application provides REST API endpoints for programmatic access:

- `GET /api/databases` - List all databases
- `POST /api/console/execute` - Execute SQL queries
- `POST /api/console/suggestions` - Get AI query suggestions
- `GET /api/system_logs` - Retrieve system logs
- `POST /start_virtual_server` - Start VDS instance
- `POST /rotate_password` - Rotate encryption password

## Contributing

We welcome contributions to CryptoPIX Bridge! Please follow these guidelines:

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Install development dependencies
4. Make your changes
5. Run tests and ensure code quality
6. Submit a pull request

### Code Standards

- Follow PEP 8 Python style guidelines
- Add docstrings to all functions and classes
- Write unit tests for new features
- Update documentation for API changes

### Reporting Issues

- Use GitHub Issues to report bugs
- Include detailed steps to reproduce
- Provide system information and error logs
- Suggest improvements with clear use cases

## Author

**CRYPTOPIX(OPC) PRIVATE LIMITED**

Contact: support@cryptopix.in

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Documentation: [docs/](docs/)
- Repository: [GitHub Repository](https://github.com/cryptopix-dev/Cryptopix-Bridge)
- Issues: [GitHub Issues](https://github.com/cryptopix-dev/Cryptopix-Bridge/issues)
- Email: support@cryptopix.in

## Security

CryptoPIX Bridge implements multiple security measures:
- CLWE encryption for data at rest
- License-based authentication
- Secure password requirements
- Audit logging and monitoring
- Encrypted communication channels

Please report security vulnerabilities directly to support@cryptopix.in.