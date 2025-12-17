/**
 * Multi-Database Management JavaScript
 * Handles UI for managing multiple databases and VDS instances
 */

// Load and display all databases
async function loadDatabases() {
    try {
        const response = await fetch('/api/databases');
        const data = await response.json();
        
        if (data.success) {
            displayDatabases(data.databases);
        } else {
            showError('Failed to load databases: ' + data.error);
        }
    } catch (error) {
        console.error('Error loading databases:', error);
        showError('Failed to load databases');
    }
}

// Display databases in the UI
function displayDatabases(databases) {
    const container = document.getElementById('databasesList');
    
    if (!container) return;
    
    if (databases.length === 0) {
        container.innerHTML = `
            <div class="text-center py-5">
                <i class="bi bi-database-x" style="font-size: 48px; color: #ccc;"></i>
                <p class="mt-3 text-muted">No databases migrated yet</p>
                <a href="/migration_setup" class="btn btn-primary">
                    <i class="bi bi-plus-circle me-1"></i>Start Your First Migration
                </a>
            </div>
        `;
        return;
    }
    
    let html = '<div class="row">';
    
    databases.forEach(db => {
        const statusBadge = db.migration_complete 
            ? '<span class="badge bg-success">Migrated</span>'
            : '<span class="badge bg-warning">In Progress</span>';
        
        const vdsCount = db.vds_instances ? db.vds_instances.length : 0;
        const runningVds = db.vds_instances ? db.vds_instances.filter(v => v.status === 'running').length : 0;
        
        html += `
            <div class="col-md-6 col-lg-4 mb-3">
                <div class="card h-100 database-card" data-db-id="${db.id}">
                    <div class="card-header bg-light">
                        <div class="d-flex justify-content-between align-items-center">
                            <h6 class="mb-0"><i class="bi bi-database me-2"></i>${db.name}</h6>
                            ${statusBadge}
                        </div>
                    </div>
                    <div class="card-body">
                        <p class="small text-muted mb-2">
                            <strong>Created:</strong> ${new Date(db.created_at).toLocaleDateString()}
                        </p>
                        <p class="small text-muted mb-2">
                            <strong>VDS Instances:</strong> ${vdsCount} (${runningVds} running)
                        </p>
                        <div class="d-grid gap-2 mt-3">
                            <a href="/query_console?db_id=${db.id}" class="btn btn-sm btn-outline-primary">
                                <i class="bi bi-terminal me-1"></i>Query Console
                            </a>
                            <a href="/settings?tab=databases&db_id=${db.id}" class="btn btn-sm btn-outline-secondary">
                                <i class="bi bi-gear me-1"></i>Manage VDS
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
}

// Create a new VDS instance
async function createVDS(dbId, host, port, protocol) {
    try {
        const response = await fetch(`/api/databases/${dbId}/vds/create`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ host, port, protocol })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(`VDS instance created successfully`);
            return data.vds_id;
        } else {
            showError('Failed to create VDS: ' + data.error);
            return null;
        }
    } catch (error) {
        console.error('Error creating VDS:', error);
        showError('Failed to create VDS instance');
        return null;
    }
}

// Start a VDS instance
async function startVDS(dbId, vdsId) {
    try {
        const response = await fetch(`/api/databases/${dbId}/vds/${vdsId}/start`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(data.message);
            return true;
        } else {
            showError('Failed to start VDS: ' + data.error);
            return false;
        }
    } catch (error) {
        console.error('Error starting VDS:', error);
        showError('Failed to start VDS instance');
        return false;
    }
}

// Stop a VDS instance
async function stopVDS(dbId, vdsId) {
    try {
        const response = await fetch(`/api/databases/${dbId}/vds/${vdsId}/stop`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess(data.message);
            return true;
        } else {
            showError('Failed to stop VDS: ' + data.error);
            return false;
        }
    } catch (error) {
        console.error('Error stopping VDS:', error);
        showError('Failed to stop VDS instance');
        return false;
    }
}

// Get VDS status
async function getVDSStatus(dbId, vdsId) {
    try {
        const response = await fetch(`/api/databases/${dbId}/vds/${vdsId}/status`);
        const data = await response.json();
        
        if (data.success) {
            return data;
        } else {
            return null;
        }
    } catch (error) {
        console.error('Error getting VDS status:', error);
        return null;
    }
}

// Delete a VDS instance
async function deleteVDS(dbId, vdsId) {
    if (!confirm('Are you sure you want to delete this VDS instance?')) {
        return false;
    }
    
    try {
        const response = await fetch(`/api/databases/${dbId}/vds/${vdsId}/delete`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showSuccess('VDS instance deleted successfully');
            return true;
        } else {
            showError('Failed to delete VDS: ' + data.error);
            return false;
        }
    } catch (error) {
        console.error('Error deleting VDS:', error);
        showError('Failed to delete VDS instance');
        return false;
    }
}

// Load VDS instances for a database
async function loadVDSInstances(dbId) {
    try {
        const response = await fetch(`/api/databases/${dbId}/vds`);
        const data = await response.json();
        
        if (data.success) {
            return data.vds_instances;
        } else {
            showError('Failed to load VDS instances: ' + data.error);
            return [];
        }
    } catch (error) {
        console.error('Error loading VDS instances:', error);
        showError('Failed to load VDS instances');
        return [];
    }
}

// Display VDS instances in the UI
function displayVDSInstances(vdsInstances, dbId, container) {
    if (!container) return;
    
    if (vdsInstances.length === 0) {
        container.innerHTML = `
            <div class="text-center py-3">
                <p class="text-muted mb-0">No VDS instances created yet</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="list-group">';
    
    vdsInstances.forEach(vds => {
        const statusClass = vds.status === 'running' ? 'success' : 'secondary';
        const statusIcon = vds.status === 'running' ? 'play-circle-fill' : 'stop-circle';
        
        html += `
            <div class="list-group-item">
                <div class="d-flex justify-content-between align-items-center">
                    <div>
                        <h6 class="mb-1">
                            <i class="bi bi-${statusIcon} text-${statusClass} me-2"></i>
                            ${vds.host}:${vds.port}
                        </h6>
                        <small class="text-muted">Protocol: ${vds.protocol} | Status: ${vds.status}</small>
                    </div>
                    <div class="btn-group btn-group-sm">
                        ${vds.status === 'running' 
                            ? `<button class="btn btn-warning" onclick="stopVDSAndReload('${dbId}', '${vds.id}')">
                                <i class="bi bi-stop-circle"></i> Stop
                               </button>`
                            : `<button class="btn btn-success" onclick="startVDSAndReload('${dbId}', '${vds.id}')">
                                <i class="bi bi-play-circle"></i> Start
                               </button>`
                        }
                        <button class="btn btn-danger" onclick="deleteVDSAndReload('${dbId}', '${vds.id}')">
                            <i class="bi bi-trash"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
}

// Helper functions for VDS actions with reload
async function startVDSAndReload(dbId, vdsId) {
    const success = await startVDS(dbId, vdsId);
    if (success) {
        setTimeout(() => location.reload(), 1000);
    }
}

async function stopVDSAndReload(dbId, vdsId) {
    const success = await stopVDS(dbId, vdsId);
    if (success) {
        setTimeout(() => location.reload(), 1000);
    }
}

async function deleteVDSAndReload(dbId, vdsId) {
    const success = await deleteVDS(dbId, vdsId);
    if (success) {
        setTimeout(() => location.reload(), 1000);
    }
}

// Show success message
function showSuccess(message) {
    showToast(message, 'success');
}

// Show error message
function showError(message) {
    showToast(message, 'error');
}

// Show toast notification
function showToast(message, type = 'info') {
    console.log('Showing toast:', message, type);

    // Create toast container if it doesn't exist
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.className = 'toast-container';
        document.body.appendChild(toastContainer);
        console.log('Created toast container');
    }

    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    toast.innerHTML = `
        <div class="toast-body">
            <strong>${type.charAt(0).toUpperCase() + type.slice(1)}:</strong> ${message}
        </div>
    `;

    // Add to container
    toastContainer.appendChild(toast);
    console.log('Added toast to container');

    // Initialize Bootstrap toast with 8-second delay
    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: 8000
    });
    bsToast.show();

    // Remove from DOM after hiding
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
        console.log('Removed toast');
    });
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Load databases if on home page
    if (document.getElementById('databasesList')) {
        loadDatabases();
    }
    
    // Load VDS instances if on settings page
    const vdsContainer = document.getElementById('vdsInstancesList');
    if (vdsContainer) {
        const dbId = vdsContainer.dataset.dbId;
        if (dbId) {
            loadVDSInstances(dbId).then(instances => {
                displayVDSInstances(instances, dbId, vdsContainer);
            });
        }
    }
});
