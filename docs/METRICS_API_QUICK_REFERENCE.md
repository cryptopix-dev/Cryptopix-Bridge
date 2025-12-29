# Metrics API - Quick Reference

## 🚀 Client APIs (CryptoPix Bridge)

### 1. Get VDS Uptime
```
GET /api/vds/uptime/<db_id>/<vds_id>
```
**Example:** `http://localhost:5000/api/vds/uptime/db_abc123/vds_xyz789`

---

### 2. Get Database Sizes
```
GET /api/metrics/database-sizes
```
**Example:** `http://localhost:5000/api/metrics/database-sizes`

---

### 3. Send Metrics to License Server ⭐
```
POST /api/metrics/send-to-license-server
```
**Example:** `http://localhost:5000/api/metrics/send-to-license-server`

**This is the main API that:**
- Collects all database metrics
- Calculates sizes and compression ratios
- Gets VDS uptime for all instances
- Sends everything to license server

---

## 🌐 License Server API (Remote)

### Receive Metrics
```
POST {LICENSE_SERVER_URL}/api/metrics/database
```
**Example:** `https://license.cryptopix.com/api/metrics/database`

**Headers:**
```
Content-Type: application/json
Authorization: Bearer {license_key}
```

---

## 📊 Data Sent to License Server

```json
{
    "user_email": "user@example.com",
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "timestamp": "2025-12-29T09:56:30+05:30",
    "databases": [
        {
            "database_name": "my_db",
            "database_id": "db_123",
            "source_size_gb": 1.0,
            "encrypted_size_gb": 1.1,
            "compression_ratio": 1.1,
            "size_increase_percent": 10.0,
            "vds_instances": [...],
            "vds_count": 1
        }
    ]
}
```

---

## 🔧 Configuration
**File:** `.env` or `app/config.py`

```env
LICENSE_SERVER_URL=https://bridge.cryptopix.in
```

### Endpoints Constructed
If `LICENSE_SERVER_URL=https://bridge.cryptopix.in`, the app will use:
- **Metrics:** `https://bridge.cryptopix.in/api/metrics/database`
- **Login:** `https://bridge.cryptopix.in/api/bridge/login`
- **Validate:** `https://bridge.cryptopix.in/api/bridge/validate`

---

## 💻 JavaScript Usage

```javascript
// Send metrics to license server
fetch('/api/metrics/send-to-license-server', {
    method: 'POST'
})
.then(res => res.json())
.then(data => {
    if (data.success) {
        console.log(`✅ Sent metrics for ${data.databases_reported} databases`);
    }
});
```

---

## 📝 What Gets Sent

For each database:
- ✅ Database name and ID
- ✅ Source database size (bytes, MB, GB)
- ✅ Encrypted database size (bytes, MB, GB)
- ✅ Compression ratio
- ✅ Size increase percentage
- ✅ Migration status
- ✅ VDS instances count
- ✅ VDS uptime for each instance
- ✅ Created/Updated timestamps (IST)

---

## 🎯 Quick Test

```bash
# 1. Start app
python run.py

# 2. Login at http://localhost:5000

# 3. Send metrics
curl -X POST http://localhost:5000/api/metrics/send-to-license-server \
  -H "Cookie: session=YOUR_SESSION"
```

---

## 📚 Full Documentation

See `METRICS_API_DOCUMENTATION.md` for complete details.
See `LICENSE_SERVER_INTEGRATION.md` for server-side implementation.
