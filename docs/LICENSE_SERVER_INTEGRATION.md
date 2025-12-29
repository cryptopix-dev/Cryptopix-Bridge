# License Server Integration Guide

## Overview
This document describes the new API endpoint and database schema needed on the license server to receive and display database metrics from CryptoPix Bridge clients.

---

## 1. Database Schema Changes

### New Table: `database_metrics`

```sql
CREATE TABLE database_metrics (
    id SERIAL PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    license_key VARCHAR(255) NOT NULL,
    database_name VARCHAR(255) NOT NULL,
    database_id VARCHAR(100) NOT NULL,
    
    -- Source Database Info
    source_size_bytes BIGINT DEFAULT 0,
    source_size_mb DECIMAL(10, 2) DEFAULT 0,
    source_size_gb DECIMAL(10, 4) DEFAULT 0,
    
    -- Encrypted Database Info
    encrypted_size_bytes BIGINT DEFAULT 0,
    encrypted_size_mb DECIMAL(10, 2) DEFAULT 0,
    encrypted_size_gb DECIMAL(10, 4) DEFAULT 0,
    
    -- Metrics
    compression_ratio DECIMAL(10, 4) DEFAULT 0,
    size_increase_percent DECIMAL(10, 2) DEFAULT 0,
    migration_complete BOOLEAN DEFAULT FALSE,
    
    -- VDS Info
    vds_count INTEGER DEFAULT 0,
    vds_instances JSONB,  -- Store VDS instance details as JSON
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reported_at TIMESTAMP NOT NULL,
    
    -- Indexes
    INDEX idx_user_email (user_email),
    INDEX idx_license_key (license_key),
    INDEX idx_database_name (database_name),
    INDEX idx_reported_at (reported_at)
);
```

### Optional: Aggregate View

```sql
CREATE VIEW user_database_summary AS
SELECT 
    user_email,
    license_key,
    COUNT(DISTINCT database_name) as total_databases,
    SUM(source_size_gb) as total_source_size_gb,
    SUM(encrypted_size_gb) as total_encrypted_size_gb,
    AVG(compression_ratio) as avg_compression_ratio,
    SUM(vds_count) as total_vds_instances,
    MAX(reported_at) as last_report_time
FROM database_metrics
GROUP BY user_email, license_key;
```

---

## 2. API Endpoint Implementation

### Endpoint: `POST /api/metrics/database`

**Purpose:** Receive database metrics from CryptoPix Bridge clients

**Authentication:** Bearer token (license key)

**Request Headers:**
```
Content-Type: application/json
Authorization: Bearer {license_key}
```

**Request Body Example:**
```json
{
    "user_email": "user@example.com",
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "timestamp": "2025-12-29T09:37:56+05:30",
    "databases": [
        {
            "database_name": "my_production_db",
            "database_id": "db_a1b2c3d4",
            "source_size_bytes": 1073741824,
            "source_size_mb": 1024.00,
            "source_size_gb": 1.0000,
            "encrypted_size_bytes": 1181116006,
            "encrypted_size_mb": 1126.40,
            "encrypted_size_gb": 1.1000,
            "compression_ratio": 1.1000,
            "size_increase_percent": 10.00,
            "migration_complete": true,
            "created_at": "2025-12-28T10:30:00+05:30",
            "updated_at": "2025-12-29T09:37:56+05:30",
            "vds_instances": [
                {
                    "vds_id": "vds_12345678",
                    "host": "0.0.0.0",
                    "port": 4406,
                    "protocol": "mysql",
                    "status": "running",
                    "uptime": {
                        "status": "running",
                        "uptime_seconds": 3600,
                        "uptime_formatted": "1h 0m 0s",
                        "uptime_days": 0,
                        "uptime_hours": 1,
                        "uptime_minutes": 0,
                        "uptime_seconds_remaining": 0,
                        "last_started": "2025-12-29T08:37:56+05:30",
                        "last_stopped": null
                    }
                }
            ],
            "vds_count": 1
        }
    ]
}
```

**Response (Success):**
```json
{
    "success": true,
    "message": "Metrics received successfully",
    "databases_processed": 1
}
```

**Response (Error):**
```json
{
    "success": false,
    "error": "Invalid license key"
}
```

---

## 3. Backend Implementation (Python/Flask Example)

```python
from flask import Flask, request, jsonify
from datetime import datetime
import psycopg2
import json

app = Flask(__name__)

@app.route('/api/metrics/database', methods=['POST'])
def receive_database_metrics():
    """Receive and store database metrics from CryptoPix Bridge clients"""
    try:
        # Get authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"success": False, "error": "Missing or invalid authorization"}), 401
        
        license_key = auth_header.replace('Bearer ', '')
        
        # Validate license key (implement your validation logic)
        if not validate_license_key(license_key):
            return jsonify({"success": False, "error": "Invalid license key"}), 401
        
        # Get request data
        data = request.get_json()
        
        if not data or 'databases' not in data:
            return jsonify({"success": False, "error": "Invalid request data"}), 400
        
        # Connect to database
        conn = psycopg2.connect(
            host="your_db_host",
            database="your_db_name",
            user="your_db_user",
            password="your_db_password"
        )
        cursor = conn.cursor()
        
        databases_processed = 0
        
        # Process each database
        for db in data['databases']:
            # Check if record exists
            cursor.execute("""
                SELECT id FROM database_metrics 
                WHERE license_key = %s AND database_id = %s
            """, (license_key, db['database_id']))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing record
                cursor.execute("""
                    UPDATE database_metrics SET
                        database_name = %s,
                        source_size_bytes = %s,
                        source_size_mb = %s,
                        source_size_gb = %s,
                        encrypted_size_bytes = %s,
                        encrypted_size_mb = %s,
                        encrypted_size_gb = %s,
                        compression_ratio = %s,
                        size_increase_percent = %s,
                        migration_complete = %s,
                        vds_count = %s,
                        vds_instances = %s,
                        updated_at = CURRENT_TIMESTAMP,
                        reported_at = %s
                    WHERE id = %s
                """, (
                    db['database_name'],
                    db['source_size_bytes'],
                    db['source_size_mb'],
                    db['source_size_gb'],
                    db['encrypted_size_bytes'],
                    db['encrypted_size_mb'],
                    db['encrypted_size_gb'],
                    db['compression_ratio'],
                    db['size_increase_percent'],
                    db['migration_complete'],
                    db['vds_count'],
                    json.dumps(db['vds_instances']),
                    datetime.fromisoformat(data['timestamp']),
                    existing[0]
                ))
            else:
                # Insert new record
                cursor.execute("""
                    INSERT INTO database_metrics (
                        user_email, license_key, database_name, database_id,
                        source_size_bytes, source_size_mb, source_size_gb,
                        encrypted_size_bytes, encrypted_size_mb, encrypted_size_gb,
                        compression_ratio, size_increase_percent, migration_complete,
                        vds_count, vds_instances, reported_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    data['user_email'],
                    license_key,
                    db['database_name'],
                    db['database_id'],
                    db['source_size_bytes'],
                    db['source_size_mb'],
                    db['source_size_gb'],
                    db['encrypted_size_bytes'],
                    db['encrypted_size_mb'],
                    db['encrypted_size_gb'],
                    db['compression_ratio'],
                    db['size_increase_percent'],
                    db['migration_complete'],
                    db['vds_count'],
                    json.dumps(db['vds_instances']),
                    datetime.fromisoformat(data['timestamp'])
                ))
            
            databases_processed += 1
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "message": "Metrics received successfully",
            "databases_processed": databases_processed
        }), 200
        
    except Exception as e:
        print(f"Error processing metrics: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


def validate_license_key(license_key):
    """Validate license key - implement your validation logic"""
    # TODO: Implement actual validation
    return True  # Placeholder
```

---

## 4. Display Dashboard Implementation

### Endpoint: `GET /api/metrics/user-databases`

**Purpose:** Get all database metrics for a user

```python
@app.route('/api/metrics/user-databases', methods=['GET'])
def get_user_databases():
    """Get all database metrics for the authenticated user"""
    try:
        # Get authorization
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"success": False, "error": "Missing authorization"}), 401
        
        license_key = auth_header.replace('Bearer ', '')
        
        # Connect to database
        conn = psycopg2.connect(...)
        cursor = conn.cursor()
        
        # Get all databases for this license key
        cursor.execute("""
            SELECT 
                database_name,
                database_id,
                source_size_gb,
                encrypted_size_gb,
                compression_ratio,
                size_increase_percent,
                migration_complete,
                vds_count,
                vds_instances,
                reported_at
            FROM database_metrics
            WHERE license_key = %s
            ORDER BY reported_at DESC
        """, (license_key,))
        
        databases = []
        for row in cursor.fetchall():
            databases.append({
                "database_name": row[0],
                "database_id": row[1],
                "source_size_gb": float(row[2]),
                "encrypted_size_gb": float(row[3]),
                "compression_ratio": float(row[4]),
                "size_increase_percent": float(row[5]),
                "migration_complete": row[6],
                "vds_count": row[7],
                "vds_instances": json.loads(row[8]) if row[8] else [],
                "reported_at": row[9].isoformat()
            })
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "success": True,
            "databases": databases,
            "total_count": len(databases)
        }), 200
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
```

---

## 5. Frontend Display (HTML/JavaScript Example)

```html
<!DOCTYPE html>
<html>
<head>
    <title>Database Metrics Dashboard</title>
    <style>
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #4CAF50; color: white; }
        .status-running { color: green; }
        .status-stopped { color: red; }
    </style>
</head>
<body>
    <h1>Your Database Metrics</h1>
    <div id="metrics-container"></div>

    <script>
        async function loadMetrics() {
            const response = await fetch('/api/metrics/user-databases', {
                headers: {
                    'Authorization': 'Bearer YOUR_LICENSE_KEY'
                }
            });
            
            const data = await response.json();
            
            if (data.success) {
                displayMetrics(data.databases);
            }
        }

        function displayMetrics(databases) {
            const container = document.getElementById('metrics-container');
            
            let html = '<table><thead><tr>';
            html += '<th>Database Name</th>';
            html += '<th>Source Size (GB)</th>';
            html += '<th>Encrypted Size (GB)</th>';
            html += '<th>Size Increase</th>';
            html += '<th>VDS Instances</th>';
            html += '<th>Last Reported</th>';
            html += '</tr></thead><tbody>';
            
            databases.forEach(db => {
                html += '<tr>';
                html += `<td><strong>${db.database_name}</strong></td>`;
                html += `<td>${db.source_size_gb.toFixed(2)} GB</td>`;
                html += `<td>${db.encrypted_size_gb.toFixed(2)} GB</td>`;
                html += `<td>${db.size_increase_percent.toFixed(2)}%</td>`;
                html += `<td>${db.vds_count} instances`;
                
                // Show VDS uptime
                if (db.vds_instances && db.vds_instances.length > 0) {
                    html += '<ul>';
                    db.vds_instances.forEach(vds => {
                        const status = vds.status === 'running' ? 'status-running' : 'status-stopped';
                        const uptime = vds.uptime ? vds.uptime.uptime_formatted : 'N/A';
                        html += `<li class="${status}">${vds.host}:${vds.port} - ${uptime}</li>`;
                    });
                    html += '</ul>';
                }
                
                html += '</td>';
                html += `<td>${new Date(db.reported_at).toLocaleString()}</td>`;
                html += '</tr>';
            });
            
            html += '</tbody></table>';
            container.innerHTML = html;
        }

        // Load metrics on page load
        loadMetrics();
    </script>
</body>
</html>
```

---

## 6. Summary

### What You Need to Add to License Server:

1. **Database Table:** `database_metrics` (see SQL schema above)
2. **API Endpoint:** `POST /api/metrics/database` (to receive metrics)
3. **Display Endpoint:** `GET /api/metrics/user-databases` (to show metrics)
4. **Frontend Dashboard:** HTML page to display metrics by database name

### Key Features:

- ✅ Tracks source and encrypted database sizes
- ✅ Calculates compression ratios and size increases
- ✅ Stores VDS instance information and uptime
- ✅ Groups data by database name
- ✅ Shows last reported timestamp
- ✅ Supports multiple databases per user

### Testing the Integration:

1. Start CryptoPix Bridge
2. Call the API: `POST /api/metrics/send-to-license-server`
3. Check license server database for new records
4. View dashboard to see metrics displayed by database name
