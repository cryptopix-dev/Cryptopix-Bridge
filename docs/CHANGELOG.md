# CryptoPix Bridge v3.0 - Recent Updates

## 🆕 Latest Features (December 2025)

### 1. ✅ Fixed Automatic Logout Issue
- **Problem:** Application was automatically logging users out due to aggressive token validation
- **Solution:** 
  - Removed token validation on every request
  - Implemented 30-day persistent sessions
  - Session now only clears on manual logout
  - Added session security with HttpOnly and SameSite cookies

### 2. 🕐 IST Timezone Support
- **All timestamps now use Indian Standard Time (IST - UTC+5:30)**
- Affects:
  - System logs
  - Migration tracking
  - Database registry
  - Audit logs
  - Schema encryption timestamps
- Timestamps include timezone info: `2025-12-29T10:16:12+05:30`

### 3. ⏱️ VDS Uptime Tracking
- **New Feature:** Track uptime for all Virtual Database Server instances
- **API Endpoint:** `GET /api/vds/uptime/<db_id>/<vds_id>`
- **Features:**
  - Real-time uptime calculation
  - Formatted display (e.g., "2d 5h 30m")
  - Last started/stopped timestamps
  - Status tracking (running/stopped)

### 4. 📊 Database Size Metrics & License Server Integration
- **New Feature:** Automatic database size tracking and reporting
- **API Endpoints:**
  - `GET /api/metrics/database-sizes` - Get local database sizes
  - `POST /api/metrics/send-to-license-server` - Send metrics to license server
- **Metrics Collected:**
  - Source database size (bytes, MB, GB)
  - Encrypted database size (bytes, MB, GB)
  - Compression ratio
  - Size increase percentage
  - VDS instance information
  - VDS uptime data
  - Migration status

### 5. 📚 Comprehensive Documentation
- **New Documentation Files:**
  - `docs/METRICS_API_DOCUMENTATION.md` - Complete API documentation
  - `docs/METRICS_API_QUICK_REFERENCE.md` - Quick reference guide
  - `docs/LICENSE_SERVER_INTEGRATION.md` - License server integration guide
  - `docs/CHANGELOG.md` - This file

---

## 🔧 Configuration Changes

### New Environment Variables
```env
LICENSE_SERVER_URL=https://your-license-server.com/api/bridge
```

### Session Configuration
- Session lifetime: 30 days
- Session cookie security: HttpOnly, SameSite=Lax
- Permanent sessions enabled

---

## 📁 New Files Added

### Application Files
- `app/utils/metrics_helper.py` - Database size calculation and metrics reporting
- `.gitignore` - Comprehensive gitignore for Python projects
- `.env.example` - Environment configuration template

### Documentation Files
- `docs/METRICS_API_DOCUMENTATION.md`
- `docs/METRICS_API_QUICK_REFERENCE.md`
- `docs/LICENSE_SERVER_INTEGRATION.md`
- `docs/CHANGELOG.md`

---

## 🔄 Modified Files

### Core Application
- `app/main.py`
  - Added IST timezone support
  - Fixed automatic logout issue
  - Added 3 new API endpoints for metrics
  - Updated session configuration

### Services
- `app/services/vds_manager.py`
  - Added `get_vds_uptime()` method for uptime tracking

- `app/services/database_registry.py`
  - Updated all timestamps to use IST

### Security
- `app/core/security.py`
  - Updated audit logging to use IST timestamps

- `app/core/schema_encryption.py`
  - Updated schema timestamps to use IST

### UI
- `static/styles.css`
  - Improved system logs page UI
  - Smaller, better-aligned action buttons
  - Enhanced hover effects
  - More compact log entries

---

## 🚀 API Endpoints Summary

### VDS Management
- `GET /api/vds/uptime/<db_id>/<vds_id>` - Get VDS uptime

### Metrics & Reporting
- `GET /api/metrics/database-sizes` - Get database size information
- `POST /api/metrics/send-to-license-server` - Send metrics to license server

---

## 📋 Breaking Changes

**None** - All changes are backward compatible

---

## 🐛 Bug Fixes

1. **Automatic Logout Issue** - Fixed aggressive token validation causing unwanted logouts
2. **Session Persistence** - Sessions now persist for 30 days instead of expiring quickly
3. **Timezone Consistency** - All timestamps now consistently use IST

---

## 🔐 Security Improvements

1. **Session Security**
   - HttpOnly cookies prevent XSS attacks
   - SameSite protection prevents CSRF attacks
   - 30-day session lifetime with proper expiration

2. **Token Handling**
   - Removed unnecessary token validation on every request
   - Token only validated on login
   - Improved error handling for network issues

---

## 📊 Performance Improvements

1. **Reduced API Calls**
   - Removed token validation on every page load
   - Fewer requests to license server
   - Better network resilience

2. **Database Size Calculation**
   - Efficient size queries for different database types
   - Support for SQLite, PostgreSQL, MySQL, SQL Server

---

## 🎯 Usage Examples

### Send Metrics to License Server
```javascript
fetch('/api/metrics/send-to-license-server', {
    method: 'POST'
})
.then(res => res.json())
.then(data => {
    console.log(`Metrics sent for ${data.databases_reported} databases`);
});
```

### Get VDS Uptime
```javascript
fetch('/api/vds/uptime/db_123/vds_456')
.then(res => res.json())
.then(data => {
    console.log(`Uptime: ${data.uptime.uptime_formatted}`);
});
```

---

## 📖 Documentation

For detailed documentation, see:
- [Metrics API Documentation](METRICS_API_DOCUMENTATION.md)
- [Quick Reference](METRICS_API_QUICK_REFERENCE.md)
- [License Server Integration](LICENSE_SERVER_INTEGRATION.md)

---

## 🙏 Credits

CryptoPix Bridge v3.0 - Post-Quantum Database Encryption Platform

---

**Last Updated:** December 29, 2025
