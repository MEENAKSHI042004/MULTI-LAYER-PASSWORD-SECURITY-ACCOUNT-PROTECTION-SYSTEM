const state = { accessToken: null, refreshToken: null, preMfaToken: null, user: null };

// --- nav ---
document.querySelectorAll('.nav button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('view-' + btn.dataset.view).classList.add('active');
    if (btn.dataset.view === 'account') loadMe();
    if (btn.dataset.view === 'dashboard') loadDashboard();
  });
});

function showMsg(id, text, kind){
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = 'msg show ' + kind;
}
function hideMsg(id){
  document.getElementById(id).className = 'msg';
}

function updateRegistrationEntropy(){
  const password = document.getElementById('reg-password').value;
  const meter = document.getElementById('reg-entropy-meter');
  const fill = document.getElementById('reg-entropy-fill');
  const label = document.getElementById('reg-entropy-label');
  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^A-Za-z0-9]/.test(password)) poolSize += 32;

  const entropyBits = poolSize ? password.length * Math.log2(poolSize) : 0;
  let strength = 'Weak';
  let className = '';
  let width = Math.min(entropyBits / 100 * 100, 100);
  if (entropyBits >= 80) {
    strength = 'Very Strong';
    className = 'very-strong';
  } else if (entropyBits >= 60) {
    strength = 'Strong';
    className = 'strong';
  } else if (entropyBits >= 40) {
    strength = 'Fair';
    className = 'fair';
  }

  meter.className = 'entropy-meter ' + className;
  fill.style.width = width + '%';
  label.textContent = 'Strength: ' + strength;
}

document.getElementById('reg-password').addEventListener('input', updateRegistrationEntropy);

function updateSessionBox(){
  document.getElementById('sess-dot').className = 'dot ' + (state.accessToken ? 'on' : 'off');
  document.getElementById('sess-state').textContent = state.accessToken ? 'signed in' : 'signed out';
  document.getElementById('sess-user').textContent = state.user ? state.user.username : '—';
  document.getElementById('sess-mfa').textContent = state.user ? (state.user.mfa_enabled ? 'enabled' : 'disabled') : '—';
}

async function api(path, opts={}){
  opts.headers = opts.headers || {};
  opts.headers['Content-Type'] = 'application/json';
  if (opts.auth === 'access' && state.accessToken) opts.headers['Authorization'] = 'Bearer ' + state.accessToken;
  if (opts.auth === 'pre_mfa' && state.preMfaToken) opts.headers['Authorization'] = 'Bearer ' + state.preMfaToken;
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch(e) {}
  return { ok: res.ok, status: res.status, data };
}

async function doRegister(){
  hideMsg('register-msg');
  const username = document.getElementById('reg-username').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const { ok, data } = await api('/api/auth/register', { method:'POST', body: JSON.stringify({username, email, password}) });
  if (ok) {
    showMsg('register-msg', 'Account created for ' + data.user.username + '. You can log in now.', 'ok');
  } else {
    showMsg('register-msg', (data.error || 'Registration failed.') + (data.details ? '\n- ' + data.details.join('\n- ') : ''), 'error');
  }
}

async function doLogin(){
  hideMsg('login-msg');
  document.getElementById('mfa-challenge-card').style.display = 'none';
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const { ok, status, data } = await api('/api/auth/login', { method:'POST', body: JSON.stringify({username, password}) });
  if (!ok) {
    let msg = data.error || 'Login failed.';
    if (status === 423 && data.retry_after_seconds) msg += ' Retry in ' + data.retry_after_seconds + 's.';
    showMsg('login-msg', msg, 'error');
    return;
  }
  if (data.mfa_required) {
    state.preMfaToken = data.pre_mfa_token;
    showMsg('login-msg', 'Password verified. Complete MFA to finish signing in.', 'info');
    document.getElementById('mfa-challenge-card').style.display = 'block';
    return;
  }
  state.accessToken = data.access_token;
  state.refreshToken = data.refresh_token;
  state.user = data.user;
  updateSessionBox();
  showMsg('login-msg', 'Signed in as ' + data.user.username + '.', 'ok');
}

async function doVerifyMfa(){
  hideMsg('mfa-challenge-msg');
  const code = document.getElementById('mfa-code').value.trim();
  const use_recovery_code = document.getElementById('mfa-use-recovery').checked;
  const { ok, data } = await api('/api/auth/verify-mfa', { method:'POST', auth:'pre_mfa', body: JSON.stringify({code, use_recovery_code}) });
  if (!ok) { showMsg('mfa-challenge-msg', data.error || 'Verification failed.', 'error'); return; }
  state.accessToken = data.access_token;
  state.refreshToken = data.refresh_token;
  state.user = data.user;
  updateSessionBox();
  showMsg('mfa-challenge-msg', 'MFA verified. Signed in as ' + data.user.username + '.', 'ok');
}

async function doMfaSetup(){
  hideMsg('mfa-setup-msg');
  if (!state.accessToken) { showMsg('mfa-setup-msg', 'Log in first.', 'error'); return; }
  const { ok, data } = await api('/api/auth/mfa/setup', { method:'POST', auth:'access' });
  if (!ok) { showMsg('mfa-setup-msg', data.error || 'Could not start MFA setup.', 'error'); return; }
  const qrUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=' + encodeURIComponent(data.provisioning_uri);
  document.getElementById('qr-area').innerHTML =
    '<div class="qr-box"><img src="' + qrUrl + '" width="160" height="160" alt="QR code"/>' +
    '<div><div class="hint">Scan with Google Authenticator / Authy, or enter manually:</div>' +
    '<div class="secret">' + data.secret + '</div></div></div>';
  document.getElementById('mfa-confirm-card').style.display = 'block';
}

async function doMfaConfirm(){
  const code = document.getElementById('mfa-confirm-code').value.trim();
  const { ok, data } = await api('/api/auth/mfa/confirm', { method:'POST', auth:'access', body: JSON.stringify({code}) });
  const area = document.getElementById('recovery-area');
  if (!ok) { area.innerHTML = ''; showMsg('mfa-setup-msg', data.error || 'Could not confirm MFA.', 'error'); return; }
  state.user.mfa_enabled = true;
  updateSessionBox();
  area.innerHTML = '<div class="msg show ok">MFA enabled. Save these recovery codes now — shown only once.</div>' +
    '<div class="recovery-codes">' + data.recovery_codes.map(c => '<div>' + c + '</div>').join('') + '</div>';
}

async function loadMe(){
  hideMsg('account-msg');
  if (!state.accessToken) { showMsg('account-msg', 'Log in first.', 'info'); document.getElementById('me-json').textContent = '—'; return; }
  const { ok, data } = await api('/api/auth/me', { auth:'access' });
  if (!ok) { showMsg('account-msg', data.error || 'Could not load session.', 'error'); return; }
  document.getElementById('me-json').textContent = JSON.stringify(data.user, null, 2);
  document.getElementById('account-username').value = data.user.username;
  document.getElementById('account-email').value = data.user.email;
  state.user = data.user;
  updateSessionBox();
}

async function doChangePassword(){
  hideMsg('cp-msg');
  if (!state.accessToken) { showMsg('cp-msg', 'Log in first.', 'error'); return; }
  const current_password = document.getElementById('cp-current').value;
  const new_password = document.getElementById('cp-new').value;
  const { ok, data } = await api('/api/auth/change-password', { method:'POST', auth:'access', body: JSON.stringify({current_password, new_password}) });
  if (!ok) { showMsg('cp-msg', (data.error || 'Could not change password.') + (data.details ? '\n- ' + data.details.join('\n- ') : ''), 'error'); return; }
  showMsg('cp-msg', 'Password updated.', 'ok');
}

async function doUpdateAccount(){
  hideMsg('account-details-msg');
  if (!state.accessToken) { showMsg('account-details-msg', 'Log in first.', 'error'); return; }
  const username = document.getElementById('account-username').value.trim();
  const email = document.getElementById('account-email').value.trim();
  const { ok, data } = await api('/api/auth/update-account', {
    method:'POST', auth:'access', body: JSON.stringify({username, email})
  });
  if (!ok) { showMsg('account-details-msg', data.error || 'Could not update account details.', 'error'); return; }
  state.user = data.user;
  updateSessionBox();
  document.getElementById('me-json').textContent = JSON.stringify(data.user, null, 2);
  showMsg('account-details-msg', 'Account details updated.', 'ok');
}

async function loadDashboard(){
  hideMsg('dash-msg');
  if (!state.accessToken) { showMsg('dash-msg', 'Log in as an admin account to load the dashboard.', 'info'); return; }

  const s = await api('/api/admin/stats', { auth:'access' });
  if (!s.ok) { showMsg('dash-msg', s.data.error || 'Could not load stats (admin only).', 'error'); return; }
  document.getElementById('stat-users').textContent = s.data.total_users;
  document.getElementById('stat-attempts').textContent = s.data.total_login_attempts;
  document.getElementById('stat-failed').textContent = s.data.failed_login_attempts;
  document.getElementById('stat-locked').textContent = s.data.active_lockouts;

  const a = await api('/api/admin/audit-log?limit=40', { auth:'access' });
  const auditBody = document.querySelector('#audit-table tbody');
  auditBody.innerHTML = (a.data.entries || []).map(e =>
    '<tr><td>' + fmtTime(e.created_at) + '</td><td>' + e.event_type + '</td><td>' + (e.user_id ?? '—') +
    '</td><td>' + (e.ip_address || '—') + '</td><td>' + (e.details || '') + '</td></tr>'
  ).join('');

  const la = await api('/api/admin/login-attempts?limit=40', { auth:'access' });
  const attemptsBody = document.querySelector('#attempts-table tbody');
  attemptsBody.innerHTML = (la.data.attempts || []).map(x =>
    '<tr><td>' + fmtTime(x.created_at) + '</td><td>' + x.username_tried + '</td><td>' + x.stage +
    '</td><td><span class="pill ' + (x.success ? 'ok">success' : 'fail">failed') + '</span></td><td>' + (x.reason || '') +
    '</td><td>' + x.ip_address + '</td></tr>'
  ).join('');

  const lo = await api('/api/admin/lockouts', { auth:'access' });
  const lockBody = document.querySelector('#lockouts-table tbody');
  lockBody.innerHTML = (lo.data.lockouts || []).map(l =>
    '<tr><td>' + l.user_id + '</td><td>' + l.lockout_number + '</td><td>' + fmtTime(l.locked_at) +
    '</td><td>' + fmtTime(l.unlock_at) + '</td><td>' + l.duration_seconds + 's</td><td>' +
    (l.active ? '<span class="pill fail">active</span>' : '<span class="pill ok">expired</span>') + '</td><td>' +
    (l.active ? '<button class="btn secondary btn-xs" onclick="doUnlock(' + l.user_id + ')">Unlock</button>' : '—') +
    '</td></tr>'
  ).join('');
}

async function doUnlock(userId){
  const { ok, data } = await api('/api/admin/unlock/' + userId, { method:'POST', auth:'access' });
  if (!ok) { showMsg('dash-msg', data.error || 'Could not unlock user.', 'error'); return; }
  showMsg('dash-msg', data.message || 'User unlocked.', 'ok');
  loadDashboard();
}

async function exportAuditLog(){
  if (!state.accessToken) { showMsg('dash-msg', 'Log in as an admin account to export the audit log.', 'info'); return; }
  const response = await fetch('/api/admin/audit-log/export', {
    headers: { 'Authorization': 'Bearer ' + state.accessToken }
  });
  if (!response.ok) {
    let data = {};
    try { data = await response.json(); } catch(e) {}
    showMsg('dash-msg', data.error || 'Could not export the audit log.', 'error');
    return;
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'audit_log.csv';
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function exportAuditLogPdf(){
  if (!state.accessToken) { showMsg('dash-msg', 'Log in as an admin account to export the audit log.', 'info'); return; }
  const response = await fetch('/api/admin/audit-log/export-pdf', {
    headers: { 'Authorization': 'Bearer ' + state.accessToken }
  });
  if (!response.ok) {
    let data = {};
    try { data = await response.json(); } catch(e) {}
    showMsg('dash-msg', data.error || 'Could not export the audit log.', 'error');
    return;
  }

  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'audit_log.pdf';
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function fmtTime(iso){
  try { return new Date(iso).toLocaleString(); } catch(e) { return iso; }
}

updateSessionBox();
