# API Documentation

CryptoPIX Bridge provides a REST API for programmatic access to its features.

## Authentication

All API endpoints require authentication. Include the license token in the Authorization header:

```
Authorization: Bearer <license_token>
```

## Endpoints

### Databases

#### GET /api/databases

List all registered databases.

**Response:**
```json
{
  "success": true,
  "databases": [
    {
      "id": "db_123",
      "name": "encrypted_db",
      "source_db_url": "mysql://...",
      "encrypted_db_url": "mysql://...",
      "migration_complete": true,
      "vds_instances": [...]
    }
  ]
}
```

#### GET /api/databases/{db_id}

Get details for a specific database.

**Parameters:**
- `db_id`: Database ID

**Response:**
```json
{
  "success": true,
  "database": {
    "id": "db_123",
    "name": "encrypted_db",
    ...
  }
}
```

### Query Console

#### POST /api/console/execute

Execute SQL queries.

**Request Body:**
```json
{
  "command": "SELECT * FROM users LIMIT 10",
  "db_id": "db_123"
}
```

**Response:**
```json
{
  "success": true,
  "query_type": "SELECT",
  "rows": [...],
  "row_count": 10,
  "columns": ["id", "name", "email"],
  "decrypted": true
}
```

#### POST /api/console/suggestions

Get AI query suggestions.

**Request Body:**
```json
{
  "query": "SELECT * FROM",
  "cursor_position": 12,
  "db_id": "db_123"
}
```

**Response:**
```json
{
  "success": true,
  "suggestions": [
    {
      "text": "users",
      "type": "table",
      "description": "Users table"
    }
  ]
}
```

#### POST /api/console/explain

Get AI explanation of a query.

**Request Body:**
```json
{
  "query": "SELECT * FROM users WHERE id = 1"
}
```

**Response:**
```json
{
  "success": true,
  "explanation": "This query selects all columns from the users table where the id equals 1."
}
```

#### POST /api/console/natural_language

Convert natural language to SQL.

**Request Body:**
```json
{
  "query": "show me all users with email ending in gmail.com"
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "sql": "SELECT * FROM users WHERE email LIKE '%gmail.com'",
    "explanation": "Converted natural language to SQL query"
  }
}
```

### System Logs

#### GET /api/system_logs

Retrieve system logs with pagination and filtering.

**Query Parameters:**
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 50)
- `level`: Log level filter (ERROR, WARNING, INFO, DEBUG)
- `source`: Source filter
- `search`: Search term
- `time_range`: Hours back (24, 168, etc.)

**Response:**
```json
{
  "success": true,
  "logs": [...],
  "pagination": {
    "page": 1,
    "per_page": 50,
    "total": 1000,
    "pages": 20,
    "has_prev": false,
    "has_next": true,
    "page_start": 1,
    "page_end": 50
  }
}
```

#### GET /api/system_logs/live

Get recent logs for real-time updates.

**Query Parameters:**
- `limit`: Number of recent logs (default: 10)

#### GET /api/system_logs/{log_id}

Get details for a specific log entry.

#### GET /api/system_logs/analytics

Get log analytics data.

**Query Parameters:**
- `hours`: Hours to analyze (default: 24)

### Virtual Database Server (VDS)

#### POST /api/databases/{db_id}/vds/create

Create a new VDS instance.

**Request Body:**
```json
{
  "host": "127.0.0.1",
  "port": 4406,
  "protocol": "mysql"
}
```

#### POST /api/databases/{db_id}/vds/{vds_id}/start

Start a VDS instance.

#### POST /api/databases/{db_id}/vds/{vds_id}/stop

Stop a VDS instance.

#### GET /api/databases/{db_id}/vds/{vds_id}/status

Get VDS instance status.

#### GET /api/databases/{db_id}/vds

List all VDS instances for a database.

#### DELETE /api/databases/{db_id}/vds/{vds_id}/delete

Delete a VDS instance.

#### GET /api/vds/running

Get all running VDS instances.

### Migration

#### GET /api/migration_progress

Get current migration progress.

**Response:**
```json
{
  "status": "running",
  "progress": 65.5,
  "current_table": "users",
  "total_tables": 10,
  "completed_tables": 6,
  "message": "Migrating table: users",
  "error": null,
  "start_time": "2023-12-01T10:00:00Z",
  "end_time": null
}
```

#### GET /api/vds_status

Get Virtual Database Server status.

## Error Handling

All API responses include a `success` field. When `success` is `false`, an `error` field will be present:

```json
{
  "success": false,
  "error": "Authentication required"
}
```

## Rate Limiting

API endpoints are rate limited to prevent abuse. If you exceed the limit, you'll receive a 429 status code.

## Data Formats

- All requests should use `Content-Type: application/json`
- All responses are in JSON format
- Dates are in ISO 8601 format
- Binary data (encrypted values) are returned as base64 strings when applicable

## SDKs and Libraries

Currently, no official SDKs are available. Use standard HTTP libraries to interact with the API.