# Installation Guide

## Prerequisites

Before installing CryptoPIX Bridge, ensure you have the following:

- **Python 3.8 or higher** - The application is built with Flask and requires Python 3.8+
- **Database Server** - One or more of: MySQL, PostgreSQL, SQLite, MSSQL, Oracle, or MongoDB
- **License Key** - Valid license key for authentication with the license server
- **System Requirements** - At least 4GB RAM, 2GB free disk space

## Installation Steps

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/cryptopix-bridge.git
cd cryptopix-bridge
```

### Step 2: Create Virtual Environment (Recommended)

It's recommended to use a virtual environment to avoid conflicts with system Python packages.

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### Step 3: Install Dependencies

Install all required Python packages:

```bash
pip install -r requirements.txt
```

This will install Flask, SQLAlchemy, cryptography libraries, and other dependencies.

### Step 4: Configure Environment Variables

Create a `.env` file in the project root directory with the following variables:

```env
# Core Configuration
CRYPTOPIX_DEFAULT_PASSWORD=your_secure_password_here
LICENSE_SERVER_URL=https://your-license-server.com/api/bridge
APP_HOST=0.0.0.0
APP_PORT=8000
DEBUG=False
SECRET_KEY=your_secret_key_here

# Database URLs (configure as needed)
SOURCE_DB_URL=mysql://user:password@localhost:3306/source_db
ENCRYPTED_DB_URL=mysql://user:password@localhost:3306/encrypted_db

# Security Settings
SECURITY_LEVEL=Medium
TAG_SALT=your_unique_salt_here

# Virtual Database Server
VDS_HOST=0.0.0.0
VDS_PORT=4406
VDS_PROTOCOL=mysql
VDS_MAX_CONNECTIONS=100
```

### Step 5: Database Setup

Ensure your target database servers are running and accessible. The application supports:

- **MySQL/MariaDB** - Version 5.7+
- **PostgreSQL** - Version 12+
- **SQLite** - Built-in, no setup required
- **Microsoft SQL Server** - Version 2016+
- **Oracle Database** - Version 12c+
- **MongoDB** - Version 4.0+

### Step 6: Run the Application

Start the CryptoPIX Bridge application:

```bash
python run.py
```

The web interface will be available at `http://localhost:8000`.

## Configuration Details

### Core Settings

- `CRYPTOPIX_DEFAULT_PASSWORD`: Default encryption password (must be strong)
- `LICENSE_SERVER_URL`: URL of the license server for authentication
- `APP_HOST`: Host to bind the Flask application (default: 0.0.0.0)
- `APP_PORT`: Port for the Flask application (default: 8000)
- `DEBUG`: Enable debug mode (set to False in production)
- `SECRET_KEY`: Flask session secret key (generate a random string)

### Database Configuration

- `SOURCE_DB_URL`: Connection URL for the source database to encrypt
- `ENCRYPTED_DB_URL`: Connection URL for the target encrypted database
- `SECURITY_LEVEL`: Encryption security level (Min/Medium/Max)
- `TAG_SALT`: Salt for consistent hashing in encryption tags

### Virtual Database Server (VDS)

- `VDS_HOST`: Host for the VDS (default: 0.0.0.0)
- `VDS_PORT`: Port for the VDS (default: 4406)
- `VDS_PROTOCOL`: Database protocol (mysql/postgresql/etc.)
- `VDS_MAX_CONNECTIONS`: Maximum concurrent connections

## Post-Installation Setup

1. **Access the Web Interface**: Open `http://localhost:8000` in your browser
2. **Login**: Use your email and license key to authenticate
3. **Configure Migration**: Set up database migration settings
4. **Run Migration**: Execute the encryption migration process

## Troubleshooting Installation

### Common Issues

**Python Version Error**
```
Error: Python 3.8 or higher required
```
Solution: Upgrade Python or use a different environment.

**Dependency Installation Fails**
```
ERROR: Could not find a version that satisfies the requirement
```
Solution: Ensure pip is up to date: `pip install --upgrade pip`

**Database Connection Error**
```
(sqlalchemy.exc.OperationalError) Connection failed
```
Solution: Check database server is running and credentials are correct.

**License Server Unreachable**
```
Connection error: HTTPSConnectionPool
```
Solution: Verify `LICENSE_SERVER_URL` and network connectivity.

For more troubleshooting help, see the [Troubleshooting Guide](troubleshooting.md).