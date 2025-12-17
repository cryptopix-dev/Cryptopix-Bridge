# User Guide

## Getting Started

After installation, access the application at `http://localhost:8000`.

### Login

1. Enter your email address
2. Enter your license key
3. Click "Login"

## Database Migration

### Step 1: Configure Database URLs

1. Navigate to the migration setup page
2. Enter your source database URL (existing database to encrypt)
3. Enter your encrypted database URL (target database for encrypted data)
4. Set encryption password and security level

### Step 2: Select Tables and Columns

1. The system will retrieve available tables from your source database
2. Select which tables to encrypt
3. For each table, choose which columns to encrypt (sensitive data is auto-detected)

### Step 3: Run Migration

1. Review your configuration
2. Click "Start Migration"
3. Monitor the progress in real-time
4. Wait for completion

## Using the Query Console

### Accessing the Console

1. From the main dashboard, click "Query Console"
2. Select a database to work with

### Writing Queries

- Write standard SQL queries
- The system automatically translates queries for encrypted data
- Use AI suggestions for query completion

### AI Features

- **Query Suggestions**: Get intelligent query suggestions
- **Natural Language**: Convert natural language to SQL
- **Query Explanation**: Understand what your queries do

## Virtual Database Server (VDS)

### Starting VDS

1. Go to Settings
2. Configure VDS parameters (host, port, protocol)
3. Click "Start Virtual Server"

### Connecting Applications

Applications can connect to the VDS using standard database connection strings:

```
mysql://user:password@localhost:4406/your_database
```

The VDS handles encryption/decryption transparently.

## Password Rotation

### Rotating Encryption Password

1. Go to Password Rotation page
2. Enter current password
3. Enter new password (must meet security requirements)
4. Confirm new password
5. Click "Rotate Password"

The system will re-encrypt all data with the new password.

## Monitoring and Logs

### System Logs

- View real-time system logs
- Filter by level, source, or time range
- Download logs in various formats

### System Health

- Monitor CPU, memory, and disk usage
- View database statistics
- Check migration progress

## Settings and Configuration

### Database Management

- View all registered databases
- Configure database connections
- Manage VDS instances

### Security Settings

- Update encryption passwords
- Configure security levels
- Manage authentication

## Best Practices

### Security

- Use strong encryption passwords
- Regularly rotate passwords
- Keep license keys secure

### Performance

- Monitor system resources
- Use appropriate security levels
- Optimize query patterns

### Backup

- Always backup data before migration
- Keep multiple copies of encryption passwords
- Test restoration procedures

## Troubleshooting

For common issues, see the [Troubleshooting Guide](troubleshooting.md).