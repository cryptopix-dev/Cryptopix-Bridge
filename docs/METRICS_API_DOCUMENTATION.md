# Metrics Transfer API - Complete Documentation

## Overview
This document explains the complete API flow for transferring database metrics from CryptoPix Bridge to the License Server.

---

## Architecture Flow

```
CryptoPix Bridge Client → License Server
     (Your App)              (Remote Server)
```

---

## 1. CLIENT SIDE (CryptoPix Bridge)

### API Endpoints Available

#### **A. Get VDS Uptime**
```
GET /api/vds/uptime/<db_id>/<vds_id>
```

**Purpose:** Get uptime information for a specific VDS instance

**URL Example:**
```
http://localhost:5000/api/vds/uptime/db_a1b2c3d4/vds_12345678
```

**Authentication:** Required (login_required decorator)

**Response:**
```json
{
    "success": true,
    "uptime": {
        "status": "running",
        "uptime_seconds": 7200,
        "uptime_formatted": "2h 0m 0s",
        "uptime_days": 0,
        "uptime_hours": 2,
        "uptime_minutes": 0,
        "uptime_seconds_remaining": 0,
        "last_started": "2025-12-29T07:56:30+05:30",
        "last_stopped": null
    }
}
```

---

#### **B. Get Database Sizes (Local)**
```
GET /api/metrics/database-sizes
```

**Purpose:** Get size information for all databases (local query, doesn't send to license server)

**URL Example:**
```
http://localhost:5000/api/metrics/database-sizes
```

**Authentication:** Required (login_required decorator)

**Response:**
```json
{
    "success": true,
    "databases": [
        {
            "database_id": "db_a1b2c3d4",
            "database_name": "my_production_db",
            "source_database": {
                "size_bytes": 1073741824,
                "size_formatted": "1.00 GB",
                "size_mb": 1024.00,
                "size_gb": 1.0000
            },
            "encrypted_database": {
                "size_bytes": 1181116006,
                "size_formatted": "1.10 GB",
                "size_mb": 1126.40,
                "size_gb": 1.1000
            },
            "compression_ratio": 1.1000,
            "size_increase_percent": 10.00,
            "created_at": "2025-12-28T10:30:00+05:30",
            "migration_complete": true
        }
    ],
    "total_databases": 1
}
```

---

#### **C. Send Metrics to License Server (Main API)**
```
POST /api/metrics/send-to-license-server
```

**Purpose:** Collect all metrics and send them to the license server

**URL Example:**
```
http://localhost:5000/api/metrics/send-to-license-server
```

**Authentication:** Required (login_required decorator)

**Method:** POST (no body required, all data collected automatically)

**What This API Does:**
1. ✅ Collects user's license key from session
2. ✅ Gathers all database information from registry
3. ✅ Calculates source database sizes
4. ✅ Calculates encrypted database sizes
5. ✅ Computes compression ratios
6. ✅ Gets VDS instance information and uptime
7. ✅ Packages everything into JSON
8. ✅ Sends to license server via HTTP POST
9. ✅ Returns success/failure response

**Response (Success):**
```json
{
    "success": true,
    "message": "Metrics sent successfully",
    "databases_reported": 2
}
```

**Response (Error):**
```json
{
    "success": false,
    "error": "License key not found"
}
```

---

### How to Call from Frontend (JavaScript)

#### **Example 1: Send Metrics to License Server**
```javascript
// Simple button click
document.getElementById('sendMetricsBtn').addEventListener('click', async () => {
    try {
        const response = await fetch('/api/metrics/send-to-license-server', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(`Success! Sent metrics for ${data.databases_reported} databases`);
        } else {
            alert(`Error: ${data.error}`);
        }
    } catch (error) {
        alert(`Failed to send metrics: ${error.message}`);
    }
});
```

#### **Example 2: Get Database Sizes First**
```javascript
async function showDatabaseSizes() {
    const response = await fetch('/api/metrics/database-sizes');
    const data = await response.json();
    
    if (data.success) {
        console.log('Total databases:', data.total_databases);
        data.databases.forEach(db => {
            console.log(`${db.database_name}:`);
            console.log(`  Source: ${db.source_database.size_formatted}`);
            console.log(`  Encrypted: ${db.encrypted_database.size_formatted}`);
            console.log(`  Increase: ${db.size_increase_percent}%`);
        });
    }
}
```

#### **Example 3: Get VDS Uptime**
```javascript
async function getVDSUptime(dbId, vdsId) {
    const response = await fetch(`/api/vds/uptime/${dbId}/${vdsId}`);
    const data = await response.json();
    
    if (data.success) {
        console.log(`VDS Status: ${data.uptime.status}`);
        console.log(`Uptime: ${data.uptime.uptime_formatted}`);
    }
}

// Usage
getVDSUptime('db_a1b2c3d4', 'vds_12345678');
```

---

## 2. DATA SENT TO LICENSE SERVER

### Outgoing Request Details

**License Server URL:** (configured in settings)
```python
settings.LICENSE_SERVER_URL = "https://your-license-server.com"
```

**Full Endpoint:**
```
POST https://your-license-server.com/api/metrics/database
```

**Headers:**
```
Content-Type: application/json
Authorization: Bearer {license_key}
```

**Request Body Structure:**
```json
{
    "user_email": "user@example.com",
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "timestamp": "2025-12-29T09:56:30+05:30",
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
            "updated_at": "2025-12-29T09:56:30+05:30",
            
            "vds_instances": [
                {
                    "vds_id": "vds_12345678",
                    "host": "0.0.0.0",
                    "port": 4406,
                    "protocol": "mysql",
                    "status": "running",
                    "uptime": {
                        "status": "running",
                        "uptime_seconds": 7200,
                        "uptime_formatted": "2h 0m 0s",
                        "uptime_days": 0,
                        "uptime_hours": 2,
                        "uptime_minutes": 0,
                        "uptime_seconds_remaining": 0,
                        "last_started": "2025-12-29T07:56:30+05:30",
                        "last_stopped": null
                    }
                }
            ],
            "vds_count": 1
        }
    ]
}
```

---

## 3. LICENSE SERVER SIDE

### Required Endpoint

**URL:**
```
POST https://your-license-server.com/api/metrics/database
```

**Authentication:** Bearer token (license key from Authorization header)

**Expected Response (Success):**
```json
{
    "success": true,
    "message": "Metrics received successfully",
    "databases_processed": 1
}
```

**Expected Response (Error):**
```json
{
    "success": false,
    "error": "Invalid license key"
}
```

---

## 4. CONFIGURATION

### In CryptoPix Bridge

**File:** `app/config.py` or `.env`

```python
# License Server Configuration (Root URL)
LICENSE_SERVER_URL = "https://your-license-server.com"
```

**Example .env:**
```env
LICENSE_SERVER_URL=https://bridge.cryptopix.in
SECRET_KEY=your-secret-key-here
```

---

## 5. COMPLETE FLOW DIAGRAM

```
┌─────────────────────────────────────────────────────────────┐
│                    CryptoPix Bridge Client                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  User clicks "Send Metrics" button                           │
│         ↓                                                     │
│  POST /api/metrics/send-to-license-server                    │
│         ↓                                                     │
│  ┌──────────────────────────────────────────────┐            │
│  │ 1. Get license_key from session              │            │
│  │ 2. Get all databases from registry           │            │
│  │ 3. For each database:                        │            │
│  │    - Calculate source DB size                │            │
│  │    - Calculate encrypted DB size             │            │
│  │    - Calculate compression ratio             │            │
│  │    - Get VDS instances                       │            │
│  │    - Get VDS uptime for each instance        │            │
│  │ 4. Package into JSON                         │            │
│  └──────────────────────────────────────────────┘            │
│         ↓                                                     │
│  send_metrics_to_license_server()                            │
│         ↓                                                     │
└─────────┼───────────────────────────────────────────────────┘
          │
          │ HTTP POST Request
          │ URL: {LICENSE_SERVER_URL}/api/metrics/database
          │ (e.g. https://bridge.cryptopix.in/api/metrics/database)
          │ Headers: Authorization: Bearer {license_key}
          │ Body: JSON with all metrics
          │
          ↓
┌─────────────────────────────────────────────────────────────┐
│                      License Server                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  POST /api/metrics/database                                  │
│         ↓                                                     │
│  ┌──────────────────────────────────────────────┐            │
│  │ 1. Validate Authorization header             │            │
│  │ 2. Verify license key                        │            │
│  │ 3. Parse JSON body                           │            │
│  │ 4. For each database:                        │            │
│  │    - Check if record exists (by database_id) │            │
│  │    - UPDATE existing or INSERT new           │            │
│  │    - Store in database_metrics table         │            │
│  │ 5. Return success response                   │            │
│  └──────────────────────────────────────────────┘            │
│         ↓                                                     │
│  Response: {"success": true, ...}                            │
│                                                               │
└─────────┼───────────────────────────────────────────────────┘
          │
          │ HTTP Response
          │
          ↓
┌─────────────────────────────────────────────────────────────┐
│                    CryptoPix Bridge Client                   │
│                                                               │
│  Receives response                                            │
│         ↓                                                     │
│  Show success/error message to user                          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. TESTING THE API

### Test Locally (Without License Server)

```bash
# 1. Start CryptoPix Bridge
python run.py

# 2. Login to the application
# Navigate to http://localhost:5000

# 3. Test getting database sizes
curl http://localhost:5000/api/metrics/database-sizes \
  -H "Cookie: session=your_session_cookie"

# 4. Test VDS uptime
curl http://localhost:5000/api/vds/uptime/db_123/vds_456 \
  -H "Cookie: session=your_session_cookie"
```

### Test with License Server

```bash
# Send metrics to license server
curl -X POST http://localhost:5000/api/metrics/send-to-license-server \
  -H "Cookie: session=your_session_cookie" \
  -H "Content-Type: application/json"
```

---

## 7. ERROR HANDLING

### Possible Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `License key not found` | User not logged in or session expired | Login again |
| `Connection error` | License server unreachable | Check LICENSE_SERVER_URL |
| `Server returned 401` | Invalid license key | Verify license key |
| `Server returned 500` | License server error | Check license server logs |
| `Failed to get database size` | Database connection issue | Verify database URLs |

---

## 8. SECURITY CONSIDERATIONS

✅ **Authentication:** Uses session-based auth + license key
✅ **HTTPS:** Should use HTTPS for license server URL in production
✅ **Authorization:** License key sent as Bearer token
✅ **Data Privacy:** Only sends metadata, not actual database content
✅ **Rate Limiting:** Consider implementing on license server

---

## 9. MONITORING & LOGGING

### CryptoPix Bridge Logs

```python
# Success
log_system_event('INFO', 'Successfully sent metrics for 2 databases to license server')

# Failure
log_system_event('WARNING', 'Failed to send metrics to license server: Connection timeout')

# Error
log_system_event('ERROR', 'Exception while sending metrics: Invalid JSON')
```

### Check Logs

```bash
# View system logs in the application
# Navigate to: http://localhost:5000/systemlog
```

---

## 10. SUMMARY

### URLs Summary

Assuming `LICENSE_SERVER_URL=https://bridge.cryptopix.in`:

| Purpose | Method | Full URL |
|---------|--------|----------|
| Login | POST | `https://bridge.cryptopix.in/api/bridge/login` |
| Validate | POST | `https://bridge.cryptopix.in/api/bridge/validate` |
| Auth Info | GET | `https://bridge.cryptopix.in/api/bridge/me` |
| Send Metrics | POST | `https://bridge.cryptopix.in/api/metrics/database` |

### Key Points

1. **Client API:** `/api/metrics/send-to-license-server` (POST)
2. **Server API:** `{LICENSE_SERVER_URL}/api/metrics/database` (POST)
3. **Authentication:** Session + License Key (Bearer token)
4. **Data Format:** JSON with database sizes, VDS uptime, compression ratios
5. **Grouping:** Data grouped by database name
6. **Timestamps:** All in IST (Indian Standard Time)

**Everything is ready to use!** 🚀
