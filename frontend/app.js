/**
 * AegisShare - Client Application Logic
 * College Capstone Project: Secure File Sharing with Expiring Access and Audit Logs
 */

// Application State
const state = {
  apiBaseUrl: localStorage.getItem('aegisshare_api_base') || 
              (window.location.protocol.startsWith('http') ? window.location.origin : 'http://127.0.0.1:8000'),
  activeView: 'view-overview',
  files: [],
  tokens: [],
  auditEvents: [],
  countdownInterval: null,
  activeTokenData: null
};

// Initialize Application on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  initApiConfig();
  initNavigation();
  initDropzone();
  initShareForm();
  initPortal();
  initAuditFilters();
  
  // Initial API Sync
  syncAllData();

  // Check URL parameters for direct recipient access (e.g. ?token=...)
  handleUrlParameters();
});

/* ==========================================================================
   API Configuration & Connection
   ========================================================================== */

function initApiConfig() {
  const inputApiUrl = document.getElementById('input-api-url');
  const activeApiHost = document.getElementById('active-api-host');
  const btnToggleConfig = document.getElementById('btn-toggle-config');
  const apiConfigBar = document.getElementById('api-config-bar');
  const btnSave = document.getElementById('btn-save-api-url');
  const btnReset = document.getElementById('btn-reset-api-url');

  inputApiUrl.value = state.apiBaseUrl;
  activeApiHost.textContent = state.apiBaseUrl;

  btnToggleConfig.addEventListener('click', () => {
    apiConfigBar.classList.toggle('hidden');
  });

  btnSave.addEventListener('click', () => {
    const rawVal = inputApiUrl.value.trim().replace(/\/+$/, '');
    if (!rawVal) return;
    state.apiBaseUrl = rawVal;
    localStorage.setItem('aegisshare_api_base', rawVal);
    activeApiHost.textContent = rawVal;
    apiConfigBar.classList.add('hidden');
    showToast('API Endpoint updated. Re-syncing...', 'info');
    syncAllData();
  });

  btnReset.addEventListener('click', () => {
    const defaultUrl = 'http://127.0.0.1:8000';
    state.apiBaseUrl = defaultUrl;
    localStorage.removeItem('aegisshare_api_base');
    inputApiUrl.value = defaultUrl;
    activeApiHost.textContent = defaultUrl;
    apiConfigBar.classList.add('hidden');
    showToast('Reset API to default.', 'info');
    syncAllData();
  });

  document.getElementById('btn-refresh-all').addEventListener('click', () => {
    syncAllData();
    showToast('Data synced with backend.', 'info');
  });
}

async function apiFetch(endpoint, options = {}) {
  const url = `${state.apiBaseUrl}${endpoint}`;
  try {
    const response = await fetch(url, options);
    return response;
  } catch (err) {
    console.error(`Fetch error for ${url}:`, err);
    updateBackendStatusBadge(false);
    throw err;
  }
}

function updateBackendStatusBadge(isHealthy, storageBackend = 'local_demo_storage') {
  const badge = document.getElementById('backend-status-badge');
  const dot = badge.querySelector('.status-dot');
  const title = badge.querySelector('.server-title');
  const statBackend = document.getElementById('stat-storage-backend');

  if (isHealthy) {
    dot.className = 'status-dot';
    title.textContent = 'API Connected';
    if (statBackend) statBackend.textContent = storageBackend;
  } else {
    dot.className = 'status-dot danger';
    title.textContent = 'Disconnected';
  }
}

async function syncAllData() {
  await Promise.allSettled([
    checkHealth(),
    fetchFiles(),
    fetchTokens(),
    fetchAudit()
  ]);
}

async function checkHealth() {
  try {
    const res = await apiFetch('/api/health');
    if (res.ok) {
      const data = await res.json();
      updateBackendStatusBadge(true, data.storage_backend);
      document.getElementById('stat-audit-events').textContent = data.total_audit_events ?? 0;
    } else {
      updateBackendStatusBadge(false);
    }
  } catch {
    updateBackendStatusBadge(false);
  }
}

/* ==========================================================================
   Navigation
   ========================================================================== */

function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const viewId = item.getAttribute('data-view');
      switchView(viewId);
    });
  });

  document.getElementById('btn-quick-upload').addEventListener('click', () => {
    switchView('view-vault');
    document.getElementById('file-input-element').click();
  });
}

function switchView(viewId) {
  state.activeView = viewId;

  // Update nav buttons
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-view') === viewId);
  });

  // Update panels
  document.querySelectorAll('.view-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === viewId);
  });

  // Update titles
  const heading = document.getElementById('page-heading');
  const subheading = document.getElementById('page-subheading');

  switch (viewId) {
    case 'view-overview':
      heading.textContent = 'Security Overview';
      subheading.textContent = 'Active security controls, cryptographic tokens, and immutable audit telemetry.';
      break;
    case 'view-vault':
      heading.textContent = 'File Vault & Upload';
      subheading.textContent = 'Store encrypted files and view existing documents ready for expiring links.';
      fetchFiles();
      break;
    case 'view-links':
      heading.textContent = 'Expiring Share Links';
      subheading.textContent = 'Generate zero-knowledge access links with TTL countdowns and download caps.';
      fetchTokens();
      break;
    case 'view-audit':
      heading.textContent = 'Immutable Audit Trail';
      subheading.textContent = 'Append-only chronological log of all security events with redaction.';
      fetchAudit();
      break;
    case 'view-recipient':
      heading.textContent = 'Download Portal';
      subheading.textContent = 'Test and verify secure expiring download links as an external recipient.';
      break;
  }
}

/* ==========================================================================
   File Vault & Uploads
   ========================================================================== */

function initDropzone() {
  const dropzone = document.getElementById('upload-dropzone');
  const fileInput = document.getElementById('file-input-element');
  const btnBrowse = document.getElementById('btn-browse-file');

  btnBrowse.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  dropzone.addEventListener('click', () => fileInput.click());

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('drag-over');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('drag-over');
  });

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag-over');
    if (e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleFileUpload(fileInput.files[0]);
    }
  });

  document.getElementById('btn-refresh-files').addEventListener('click', fetchFiles);
}

async function handleFileUpload(file) {
  const progressBox = document.getElementById('upload-progress-box');
  const barFill = document.getElementById('upload-bar-fill');
  const filenameEl = document.getElementById('upload-filename');
  const percentEl = document.getElementById('upload-percent');
  const alertBox = document.getElementById('upload-alert-box');

  progressBox.classList.remove('hidden');
  alertBox.classList.add('hidden');
  filenameEl.textContent = file.name;
  barFill.style.width = '30%';
  percentEl.textContent = '30%';

  try {
    const formData = new FormData();
    formData.append('file', file);

    barFill.style.width = '65%';
    percentEl.textContent = '65%';

    const res = await apiFetch('/api/upload', {
      method: 'POST',
      body: formData
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Upload failed with HTTP ${res.status}`);
    }

    const data = await res.json();
    barFill.style.width = '100%';
    percentEl.textContent = '100%';

    setTimeout(() => {
      progressBox.classList.add('hidden');
      alertBox.className = 'alert-box success';
      alertBox.textContent = `File "${data.filename}" uploaded successfully (ID: ${data.file_id}).`;
      alertBox.classList.remove('hidden');
    }, 500);

    showToast(`Uploaded: ${data.filename}`, 'success');
    fetchFiles();
    fetchAudit();

  } catch (err) {
    progressBox.classList.add('hidden');
    alertBox.className = 'alert-box danger';
    alertBox.textContent = `Upload error: ${err.message}`;
    alertBox.classList.remove('hidden');
    showToast(`Upload failed: ${err.message}`, 'danger');
  }
}

async function fetchFiles() {
  const tbody = document.getElementById('tbody-files');
  const selectShare = document.getElementById('select-share-file');
  const statTotalFiles = document.getElementById('stat-total-files');

  try {
    const res = await apiFetch('/api/files');
    if (!res.ok) throw new Error('Failed to load files');
    const data = await res.json();
    state.files = data.files || [];

    statTotalFiles.textContent = state.files.length;

    // Update Vault Table
    if (state.files.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted">No files in vault. Upload one above!</td></tr>`;
    } else {
      tbody.innerHTML = state.files.map(f => `
        <tr>
          <td><code class="code-font">${escapeHtml(f.file_id)}</code></td>
          <td class="font-semibold">${escapeHtml(f.original_filename)}</td>
          <td>${formatBytes(f.file_size_bytes)}</td>
          <td><span class="badge-tag">${escapeHtml(f.content_type)}</span></td>
          <td class="text-muted text-sm">${formatUtcDate(f.uploaded_at_utc)}</td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="prepareShareForFile('${f.file_id}')">
              Create Share Link
            </button>
          </td>
        </tr>
      `).join('');
    }

    // Update Share dropdown
    selectShare.innerHTML = '<option value="">-- Select a file from Vault --</option>' +
      state.files.map(f => `<option value="${f.file_id}">${escapeHtml(f.original_filename)} (${f.file_id})</option>`).join('');

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-danger">Error loading files: ${err.message}</td></tr>`;
  }
}

window.prepareShareForFile = function(fileId) {
  switchView('view-links');
  const selectShare = document.getElementById('select-share-file');
  selectShare.value = fileId;
};

/* ==========================================================================
   Share Link Generation & Revocation
   ========================================================================== */

function initShareForm() {
  const form = document.getElementById('form-create-share');
  const selectTtl = document.getElementById('select-share-ttl');
  const groupCustomTtl = document.getElementById('group-custom-ttl');
  const inputCustomTtl = document.getElementById('input-custom-ttl');

  const selectDownloads = document.getElementById('select-max-downloads');
  const groupCustomDownloads = document.getElementById('group-custom-downloads');
  const inputCustomDownloads = document.getElementById('input-custom-downloads');

  const generatedBox = document.getElementById('generated-link-box');
  const inputGenLink = document.getElementById('input-generated-link');
  const btnCopy = document.getElementById('btn-copy-link');
  const btnTestPortal = document.getElementById('btn-test-link-in-portal');

  selectTtl.addEventListener('change', () => {
    groupCustomTtl.classList.toggle('hidden', selectTtl.value !== 'custom');
  });

  selectDownloads.addEventListener('change', () => {
    groupCustomDownloads.classList.toggle('hidden', selectDownloads.value !== 'custom');
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fileId = document.getElementById('select-share-file').value;
    if (!fileId) {
      showToast('Please select a file to share.', 'danger');
      return;
    }

    let expiresIn = parseInt(selectTtl.value, 10);
    if (selectTtl.value === 'custom') {
      expiresIn = parseInt(inputCustomTtl.value, 10);
      if (!expiresIn || expiresIn <= 0) {
        showToast('Please enter a valid TTL in seconds.', 'danger');
        return;
      }
    }

    let maxDownloads = null;
    if (selectDownloads.value === 'custom') {
      maxDownloads = parseInt(inputCustomDownloads.value, 10) || null;
    } else if (selectDownloads.value) {
      maxDownloads = parseInt(selectDownloads.value, 10);
    }

    try {
      const payload = {
        file_id: fileId,
        expires_in_seconds: expiresIn,
        max_downloads: maxDownloads
      };

      const res = await apiFetch('/api/share', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
      }

      const data = await res.json();
      
      // Build client-friendly share URL that points directly to portal
      const portalUrl = `${window.location.origin}${window.location.pathname}?token=${data.raw_token}`;
      inputGenLink.value = portalUrl;
      inputGenLink.dataset.rawToken = data.raw_token;

      document.getElementById('gen-expires-tag').textContent = `Expires: ${formatUtcDate(data.expires_at_utc)}`;
      generatedBox.classList.remove('hidden');

      showToast('Secure share link generated!', 'success');
      fetchTokens();
      fetchAudit();

    } catch (err) {
      showToast(`Failed to generate link: ${err.message}`, 'danger');
    }
  });

  btnCopy.addEventListener('click', () => {
    copyToClipboard(inputGenLink.value);
    showToast('Share link copied to clipboard!', 'info');
  });

  btnTestPortal.addEventListener('click', () => {
    const rawToken = inputGenLink.dataset.rawToken;
    if (rawToken) {
      switchView('view-recipient');
      document.getElementById('input-recipient-token').value = rawToken;
      inspectToken(rawToken);
    }
  });

  document.getElementById('btn-refresh-tokens').addEventListener('click', fetchTokens);
}

async function fetchTokens() {
  const tbody = document.getElementById('tbody-tokens');
  const statActive = document.getElementById('stat-active-links');

  try {
    const res = await apiFetch('/api/tokens');
    if (!res.ok) throw new Error('Failed to load tokens');
    const data = await res.json();
    state.tokens = data.tokens || [];

    // Filter active valid tokens
    const activeCount = state.tokens.filter(t => t.status === 'VALID').length;
    statActive.textContent = activeCount;

    if (state.tokens.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted">No share links generated yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = state.tokens.map(t => {
      let badgeClass = 'green';
      if (t.status === 'EXPIRED') badgeClass = 'amber';
      if (t.status === 'EXHAUSTED') badgeClass = 'purple';
      if (t.status === 'REVOKED') badgeClass = 'rose';

      const downloadDisplay = t.max_downloads !== null 
        ? `${t.download_count} / ${t.max_downloads}` 
        : `${t.download_count} (unlimited)`;

      const isRevokable = t.status === 'VALID';

      return `
        <tr>
          <td><code class="code-font">${escapeHtml(t.token_prefix)}</code></td>
          <td class="font-semibold">${escapeHtml(t.filename)}</td>
          <td><span class="badge-tag ${badgeClass}">${t.status}</span></td>
          <td>${downloadDisplay}</td>
          <td class="text-muted text-sm">${formatUtcDate(t.expires_at_utc)}</td>
          <td>
            ${isRevokable ? `
              <button class="btn btn-danger btn-sm" onclick="revokeTokenHash('${t.token_hash}')">
                Revoke Link
              </button>
            ` : `<span class="text-muted text-sm">Inactive</span>`}
          </td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-danger">Error loading tokens: ${err.message}</td></tr>`;
  }
}

window.revokeTokenHash = async function(tokenHash) {
  if (!confirm('Are you sure you want to revoke access for this share link immediately?')) return;

  try {
    const res = await apiFetch('/api/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token_hash: tokenHash })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    showToast('Token revoked successfully.', 'success');
    fetchTokens();
    fetchAudit();

  } catch (err) {
    showToast(`Revocation failed: ${err.message}`, 'danger');
  }
};

/* ==========================================================================
   Audit Trail Telemetry
   ========================================================================== */

function initAuditFilters() {
  const filterType = document.getElementById('filter-audit-type');
  const filterOutcome = document.getElementById('filter-audit-outcome');
  const btnRefresh = document.getElementById('btn-refresh-audit');

  filterType.addEventListener('change', fetchAudit);
  filterOutcome.addEventListener('change', fetchAudit);
  btnRefresh.addEventListener('click', fetchAudit);
}

async function fetchAudit() {
  const tbody = document.getElementById('tbody-audit');
  const overviewFeed = document.getElementById('overview-events-list');
  const typeFilter = document.getElementById('filter-audit-type').value;
  const outcomeFilter = document.getElementById('filter-audit-outcome').value;

  let query = '/api/audit?limit=100';
  if (typeFilter) query += `&event_type=${encodeURIComponent(typeFilter)}`;

  try {
    const res = await apiFetch(query);
    if (!res.ok) throw new Error('Failed to load audit logs');
    const data = await res.json();
    let events = data.events || [];

    if (outcomeFilter) {
      events = events.filter(e => e.outcome === outcomeFilter);
    }

    state.auditEvents = events;

    // Render Full Table
    if (events.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-muted">No audit events match current filters.</td></tr>`;
    } else {
      tbody.innerHTML = events.map(e => {
        let outcomeBadge = 'green';
        if (e.outcome === 'DENIED') outcomeBadge = 'rose';
        if (e.outcome === 'ERROR') outcomeBadge = 'amber';

        let detailText = e.reason || '';
        if (!detailText && e.details) {
          detailText = Object.entries(e.details)
            .map(([k, v]) => `${k}: ${v}`)
            .join(', ');
        }

        return `
          <tr>
            <td class="code-font text-muted text-sm">${formatUtcDate(e.timestamp_utc)}</td>
            <td><strong>${escapeHtml(e.event_type)}</strong></td>
            <td><span class="badge-tag ${outcomeBadge}">${escapeHtml(e.outcome)}</span></td>
            <td><code class="code-font">${escapeHtml(e.file_id)}</code></td>
            <td><code class="code-font">${escapeHtml(e.token_hash_prefix || '—')}</code></td>
            <td class="text-muted text-sm">${escapeHtml(e.actor_ip)}</td>
            <td class="text-sm">${escapeHtml(detailText || '—')}</td>
          </tr>
        `;
      }).join('');
    }

    // Render Overview Mini-Feed (top 5)
    const recent5 = events.slice(0, 5);
    if (recent5.length === 0) {
      overviewFeed.innerHTML = '<div class="empty-state"><p>No audit events recorded yet.</p></div>';
    } else {
      overviewFeed.innerHTML = recent5.map(e => {
        let bulletClass = 'green';
        if (e.outcome === 'DENIED') bulletClass = 'rose';
        if (e.outcome === 'ERROR') bulletClass = 'amber';

        return `
          <div class="feature-item" style="padding: 10px 0; border-bottom: 1px solid var(--border-subtle);">
            <div class="feature-bullet ${bulletClass}"></div>
            <div style="flex: 1;">
              <div style="display: flex; justify-content: space-between; align-items: center;">
                <strong>${escapeHtml(e.event_type)}</strong>
                <span class="text-muted text-sm">${formatTimeAgo(e.timestamp_utc)}</span>
              </div>
              <p class="text-sm" style="margin-top: 2px;">
                File: <code class="code-font">${escapeHtml(e.file_id)}</code> | Outcome: <span class="badge-tag ${bulletClass}" style="padding: 1px 5px;">${e.outcome}</span>
                ${e.reason ? ` — <em>${escapeHtml(e.reason)}</em>` : ''}
              </p>
            </div>
          </div>
        `;
      }).join('');
    }

  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-danger">Error loading audit: ${err.message}</td></tr>`;
  }
}

/* ==========================================================================
   Recipient Portal
   ========================================================================== */

function initPortal() {
  const btnInspect = document.getElementById('btn-inspect-token');
  const inputToken = document.getElementById('input-recipient-token');
  const btnDownload = document.getElementById('btn-portal-download');

  btnInspect.addEventListener('click', () => {
    const rawToken = inputToken.value.trim();
    if (!rawToken) {
      showToast('Please enter an access token.', 'danger');
      return;
    }
    inspectToken(rawToken);
  });

  inputToken.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') btnInspect.click();
  });

  btnDownload.addEventListener('click', () => {
    if (!state.activeTokenData || !state.activeTokenData.rawToken) return;
    executeDownload(state.activeTokenData.rawToken);
  });
}

async function inspectToken(rawToken) {
  const inspectBox = document.getElementById('token-inspect-box');
  const errorBox = document.getElementById('portal-error-box');
  const badgeStatus = document.getElementById('badge-token-status');
  const fnEl = document.getElementById('portal-filename');
  const fsEl = document.getElementById('portal-filesize');
  const expEl = document.getElementById('portal-expiry-utc');
  const downEl = document.getElementById('portal-downloads-remaining');
  const countdownEl = document.getElementById('portal-countdown-timer');
  const btnDownload = document.getElementById('btn-portal-download');

  clearInterval(state.countdownInterval);
  errorBox.classList.add('hidden');
  inspectBox.classList.add('hidden');

  try {
    const res = await apiFetch(`/api/tokens/inspect?token=${encodeURIComponent(rawToken)}`);
    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.message || data.error || `HTTP ${res.status}`);
    }

    state.activeTokenData = { ...data, rawToken };

    badgeStatus.className = 'badge-tag green';
    badgeStatus.textContent = data.status;

    fnEl.textContent = data.filename;
    fsEl.textContent = formatBytes(data.file_size_bytes);
    expEl.textContent = formatUtcDate(data.expires_at_utc);
    downEl.textContent = data.downloads_remaining !== null 
      ? `${data.downloads_remaining} downloads left` 
      : 'Unlimited (until expiry)';

    btnDownload.disabled = false;
    btnDownload.className = 'btn btn-primary btn-lg w-full';

    // Start live countdown timer
    startCountdown(data.expires_at_utc, countdownEl);

    inspectBox.classList.remove('hidden');

  } catch (err) {
    errorBox.className = 'alert-box danger';
    errorBox.innerHTML = `<strong>Access Denied:</strong> ${escapeHtml(err.message)}`;
    errorBox.classList.remove('hidden');
  }
}

function startCountdown(expiresAtUtc, el) {
  function update() {
    const now = new Date().getTime();
    const expiry = new Date(expiresAtUtc).getTime();
    const distance = expiry - now;

    if (distance <= 0) {
      clearInterval(state.countdownInterval);
      el.textContent = 'LINK EXPIRED';
      el.style.color = 'var(--status-danger)';
      const btn = document.getElementById('btn-portal-download');
      if (btn) {
        btn.disabled = true;
        btn.className = 'btn btn-secondary btn-lg w-full';
      }
      return;
    }

    const hours = Math.floor(distance / (1000 * 60 * 60));
    const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((distance % (1000 * 60)) / 1000);

    el.textContent = `Expires in: ${hours}h ${minutes}m ${seconds}s`;
    el.style.color = distance < 60000 ? 'var(--status-danger)' : 'var(--accent-cyan)';
  }

  update();
  state.countdownInterval = setInterval(update, 1000);
}

function executeDownload(rawToken) {
  const downloadUrl = `${state.apiBaseUrl}/api/download?token=${encodeURIComponent(rawToken)}`;
  
  // Direct file trigger
  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = '';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);

  showToast('Download initiated. Refreshing token status...', 'info');

  // Re-inspect status after brief delay to show decremented download count
  setTimeout(() => {
    inspectToken(rawToken);
    fetchTokens();
    fetchAudit();
  }, 1000);
}

function handleUrlParameters() {
  const urlParams = new URLSearchParams(window.location.search);
  const tokenParam = urlParams.get('token');
  if (tokenParam) {
    switchView('view-recipient');
    document.getElementById('input-recipient-token').value = tokenParam;
    inspectToken(tokenParam);
  }
}

/* ==========================================================================
   Utilities
   ========================================================================== */

function formatBytes(bytes, decimals = 1) {
  if (!bytes || bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatUtcDate(isoString) {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  } catch {
    return isoString;
  }
}

function formatTimeAgo(isoString) {
  if (!isoString) return '';
  try {
    const diffSec = Math.floor((new Date() - new Date(isoString)) / 1000);
    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return `${Math.floor(diffSec / 86400)}d ago`;
  } catch {
    return '';
  }
}

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text);
  } else {
    const input = document.createElement('textarea');
    input.value = text;
    document.body.appendChild(input);
    input.select();
    document.execCommand('copy');
    document.body.removeChild(input);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}
