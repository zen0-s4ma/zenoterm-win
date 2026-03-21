(() => {
const els = {
  loginScreen: document.getElementById('loginScreen'),
  loginForm: document.getElementById('loginForm'),
  loginPassword: document.getElementById('loginPassword'),
  loginMessage: document.getElementById('loginMessage'),
  logoutBtn: document.getElementById('logoutBtn'),
  defaultTargetSelect: document.getElementById('defaultTargetSelect'),
  defaultScrollbackSelect: document.getElementById('defaultScrollbackSelect'),
  globalInfo: document.getElementById('globalInfo'),
  newTabName: document.getElementById('newTabName'),
  newTabTargetSelect: document.getElementById('newTabTargetSelect'),
  newTabBtn: document.getElementById('newTabBtn'),
  targetSelect: document.getElementById('targetSelect'),
  scrollbackSelect: document.getElementById('scrollbackSelect'),
  credentialFields: document.getElementById('credentialFields'),
  connectBtn: document.getElementById('connectBtn'),
  restartBtn: document.getElementById('restartBtn'),
  clearBtn: document.getElementById('clearBtn'),
  copyBtn: document.getElementById('copyBtn'),
  saveBtn: document.getElementById('saveBtn'),
  tabsList: document.getElementById('tabsList'),
  terminalStack: document.getElementById('terminalStack'),
  statusLine: document.getElementById('statusLine'),
  targetInfo: document.getElementById('targetInfo'),
  appSubtitle: document.getElementById('appSubtitle'),
};

let runtimeConfig = null;
let authStatus = { authenticated: false };
let tabs = [];
let activeTabId = null;

const uid = (prefix = 'tab') => `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
const getActiveTab = () => tabs.find((tab) => tab.id === activeTabId) || null;
const getTargetById = (id) => runtimeConfig.targets.find((target) => target.id === id) || null;
const setStatus = (text) => { els.statusLine.textContent = text; };

function ensureAuthenticatedUi() {
  const hidden = !(runtimeConfig?.auth?.login_required) || authStatus.authenticated;
  els.loginScreen.classList.toggle('hidden', hidden);
}

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  let data = {};
  try { data = await response.json(); } catch {}
  if (!response.ok) throw new Error(data.message || data.error || `HTTP ${response.status}`);
  return data;
}

function buildGlobalInfo() {
  const loginText = runtimeConfig.auth.login_required ? 'sí' : 'no';
  const locals = runtimeConfig.targets.filter((t) => t.mode === 'direct').length;
  const remotes = runtimeConfig.targets.length - locals;
  els.globalInfo.textContent = [
    `Login requerido: ${loginText}`,
    `Targets definidos: ${runtimeConfig.targets.length}`,
    `Locales: ${locals} · Remotos: ${remotes}`,
    'Los targets remotos piden host, puerto, usuario y credenciales dentro de cada pestaña.',
  ].join('\n');
}

function fillSelect(select, selectedValue = '') {
  select.innerHTML = '';
  for (const target of runtimeConfig.targets) {
    const option = document.createElement('option');
    option.value = target.id;
    option.textContent = target.label;
    if (target.id === selectedValue) option.selected = true;
    select.appendChild(option);
  }
}

function targetSummary(target, tab) {
  const lines = [];
  if (target.mode === 'direct') {
    lines.push(`Shell local: ${target.label}`);
  } else {
    lines.push(`Host: ${tab.credentials.host || target.host || '(pendiente)'}`);
    lines.push(`Puerto: ${tab.credentials.port || target.port || 22}`);
    lines.push(`Usuario: ${tab.credentials.username || target.username || '(pendiente)'}`);
    if (target.mode === 'ssh_key') lines.push(`Clave privada: ${tab.credentials.private_key_path || target.private_key_path || '(pendiente)'}`);
    lines.push(`Shell remota a lanzar: ${target.startup_command || '(shell por defecto remota)'}`);
    lines.push(`Host key estricta: ${target.strict_host_key ? 'sí' : 'no'}`);
  }
  return lines;
}

function describeTarget(target, tab) {
  if (!target || !tab) return 'Sin pestaña activa.';
  const lines = [
    `Nombre: ${tab.title}`,
    `Target: ${target.label}`,
    `Estado: ${tab.lastStatus}`,
    `Modo: ${target.mode}`,
    target.description || '',
    ...targetSummary(target, tab),
    `Scrollback: ${Number(tab.scrollback || 0).toLocaleString('es-ES')}`,
    `Conectada: ${tab.connected ? 'sí' : 'no'}`,
  ];
  return lines.filter(Boolean).join('\n');
}

function credentialFieldHtml(kind, label, value = '', type = 'text', placeholder = '') {
  return `<label class="field"><span>${label}</span><input data-cred="${kind}" type="${type}" value="${value || ''}" placeholder="${placeholder || ''}" autocomplete="off"></label>`;
}

function renderCredentialFields() {
  const tab = getActiveTab();
  const target = tab ? getTargetById(tab.targetId) : null;
  els.targetInfo.textContent = describeTarget(target, tab);
  els.credentialFields.innerHTML = '';
  if (!tab || !target) return;

  const chunks = [];
  if (target.mode.startsWith('ssh')) {
    chunks.push(credentialFieldHtml('host', 'Host remoto', tab.credentials.host || target.host || '', 'text', 'Ej. 192.168.1.50 o servidor.example.com'));
    chunks.push(credentialFieldHtml('port', 'Puerto SSH', String(tab.credentials.port || target.port || 22), 'number', '22'));
    chunks.push(credentialFieldHtml('username', 'Usuario SSH', tab.credentials.username || target.username || '', 'text', 'Ej. admin'));
  }
  if (target.mode === 'ssh_password') {
    chunks.push(credentialFieldHtml('password', 'Contraseña SSH efímera', tab.credentials.password || '', 'password', 'Solo para esta pestaña'));
    chunks.push('<div class="credential-note">La contraseña no se guarda en disco y solo vive en memoria en esta pestaña.</div>');
  }
  if (target.mode === 'ssh_key') {
    chunks.push(credentialFieldHtml('private_key_path', 'Ruta de clave privada', tab.credentials.private_key_path || target.private_key_path || '', 'text', 'Ej. C:\\Users\\TuUsuario\\.ssh\\id_ed25519'));
    chunks.push(credentialFieldHtml('passphrase', 'Passphrase efímera', tab.credentials.passphrase || '', 'password', 'Vacía si tu clave no tiene passphrase'));
    chunks.push('<div class="credential-note">La passphrase no se guarda. La ruta de la clave puede venir del target o escribirse por pestaña.</div>');
  }
  els.credentialFields.innerHTML = chunks.join('');
  els.credentialFields.querySelectorAll('[data-cred]').forEach((input) => {
    input.addEventListener('input', () => {
      updateActiveTabState();
      const active = getActiveTab();
      if (active) els.targetInfo.textContent = describeTarget(getTargetById(active.targetId), active);
    });
  });
}

function createTerminalForPane(host, scrollback) {
  const term = new Terminal({
    cursorBlink: true,
    convertEol: true,
    scrollback: Number(scrollback),
    fontFamily: 'Cascadia Mono, Consolas, Menlo, monospace',
    fontSize: 15,
    lineHeight: 1.2,
    theme: {
      background: '#090304',
      foreground: '#f7edf0',
      cursor: '#f1c8cf',
      selectionBackground: 'rgba(195, 74, 96, 0.28)',
    },
  });
  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(host);
  fitAddon.fit();
  return { term, fitAddon };
}

function buildWsUrl() {
  return `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;
}

function currentCredentials() {
  const tab = getActiveTab();
  const target = tab ? getTargetById(tab.targetId) : null;
  const credentials = { ...(tab?.credentials || {}) };
  if (!target) return credentials;
  els.credentialFields.querySelectorAll('[data-cred]').forEach((input) => {
    const key = input.dataset.cred;
    credentials[key] = input.type === 'number' ? Number(input.value || 0) : input.value || '';
  });
  return credentials;
}

function updateActiveTabState() {
  const tab = getActiveTab();
  if (!tab) return null;
  tab.targetId = els.targetSelect.value;
  tab.scrollback = Number(els.scrollbackSelect.value);
  tab.credentials = currentCredentials();
  els.targetInfo.textContent = describeTarget(getTargetById(tab.targetId), tab);
  return tab;
}

function activateTab(tabId) {
  activeTabId = tabId;
  renderTabs();
  syncActiveTabToControls();
}

function syncActiveTabToControls() {
  const tab = getActiveTab();
  if (!tab) return;
  els.targetSelect.value = tab.targetId || runtimeConfig.targets[0]?.id || '';
  els.scrollbackSelect.value = String(tab.scrollback || 20000);
  renderCredentialFields();
  setStatus(`${tab.title} · ${tab.lastStatus}`);
  setTimeout(() => {
    tab.fitAddon.fit();
    tab.term.focus();
  }, 0);
}

function renderTabs() {
  els.tabsList.innerHTML = '';
  for (const tab of tabs) {
    const chip = document.createElement('div');
    chip.className = `tab-chip ${tab.id === activeTabId ? 'active' : ''}`;
    chip.innerHTML = `<span>${tab.connected ? '●' : '○'} ${tab.title}</span>`;
    chip.addEventListener('click', () => activateTab(tab.id));

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.textContent = '×';
    closeBtn.addEventListener('click', (event) => {
      event.stopPropagation();
      closeTab(tab.id);
    });

    chip.appendChild(closeBtn);
    els.tabsList.appendChild(chip);
    tab.pane.classList.toggle('active', tab.id === activeTabId);
  }
}

function openSocketForTab(tab, actionType = 'start') {
  if (tab.socket && tab.socket.readyState === WebSocket.OPEN) {
    sendStartPayload(tab, actionType);
    return;
  }

  tab.socket = new WebSocket(buildWsUrl());
  tab.socket.addEventListener('open', () => {
    tab.state = 'socket-open';
    sendStartPayload(tab, actionType);
  });

  tab.socket.addEventListener('message', (event) => {
    const payload = JSON.parse(event.data);
    if (payload.type === 'output') {
      tab.term.write(payload.data);
      return;
    }
    if (payload.type === 'status') {
      tab.lastStatus = payload.message || payload.status;
      tab.connected = payload.status === 'connected';
      if (payload.status === 'closed' || payload.status === 'error') tab.connected = false;
      if (payload.status === 'error') tab.term.writeln(`\r\n[ERROR] ${payload.message}\r\n`);
      if (tab.id === activeTabId) {
        setStatus(`${tab.title} · ${tab.lastStatus}`);
        els.targetInfo.textContent = describeTarget(getTargetById(tab.targetId), tab);
      }
      renderTabs();
    }
  });

  tab.socket.addEventListener('close', () => {
    tab.connected = false;
    tab.lastStatus = 'Conexión cerrada';
    if (tab.id === activeTabId) {
      setStatus(`${tab.title} · conexión cerrada`);
      els.targetInfo.textContent = describeTarget(getTargetById(tab.targetId), tab);
    }
    renderTabs();
  });

  tab.socket.addEventListener('error', () => {
    tab.connected = false;
    tab.lastStatus = 'Error de WebSocket';
    if (tab.id === activeTabId) setStatus(`${tab.title} · error de WebSocket`);
    renderTabs();
  });
}

function sendStartPayload(tab, type = 'start') {
  const target = getTargetById(tab.targetId);
  if (!target) {
    setStatus('Selecciona un target válido.');
    return;
  }
  tab.fitAddon.fit();
  tab.term.reset();
  tab.lastStatus = `${type === 'restart' ? 'Reconectando' : 'Conectando'} a ${target.label}…`;
  tab.connected = false;
  const payload = {
    type,
    target_id: tab.targetId,
    cols: tab.term.cols,
    rows: tab.term.rows,
    credentials: tab.credentials || {},
  };
  tab.socket.send(JSON.stringify(payload));
  renderTabs();
  if (tab.id === activeTabId) {
    setStatus(`${tab.title} · ${tab.lastStatus}`);
    els.targetInfo.textContent = describeTarget(target, tab);
  }
}

function createTab(config = {}) {
  const pane = document.createElement('div');
  pane.className = 'terminal-pane';
  const host = document.createElement('div');
  host.className = 'terminal-host';
  pane.appendChild(host);
  els.terminalStack.appendChild(pane);

  const scrollback = Number(config.scrollback || els.defaultScrollbackSelect.value || 20000);
  const { term, fitAddon } = createTerminalForPane(host, scrollback);
  const tab = {
    id: uid(),
    title: config.title || `Pestaña ${tabs.length + 1}`,
    targetId: config.targetId || runtimeConfig.targets[0]?.id || '',
    scrollback,
    credentials: {},
    pane,
    host,
    term,
    fitAddon,
    socket: null,
    connected: false,
    state: 'idle',
    lastStatus: 'Sin iniciar',
  };

  term.onData((data) => {
    if (tab.socket && tab.socket.readyState === WebSocket.OPEN) {
      tab.socket.send(JSON.stringify({ type: 'input', data }));
    }
  });

  term.onResize(({ cols, rows }) => {
    if (tab.socket && tab.socket.readyState === WebSocket.OPEN) {
      tab.socket.send(JSON.stringify({ type: 'resize', cols, rows }));
    }
  });

  tabs.push(tab);
  activateTab(tab.id);
  renderTabs();
  return tab;
}

function closeTab(tabId) {
  const index = tabs.findIndex((tab) => tab.id === tabId);
  if (index === -1) return;
  const tab = tabs[index];
  try {
    if (tab.socket && tab.socket.readyState === WebSocket.OPEN) {
      tab.socket.send(JSON.stringify({ type: 'close' }));
      tab.socket.close();
    }
  } catch {}
  try { tab.term.dispose(); } catch {}
  tab.pane.remove();
  tabs.splice(index, 1);
  if (!tabs.length) {
    createTab();
    return;
  }
  activateTab(tabs[Math.max(0, index - 1)].id);
}

function applyScrollbackToActiveTab() {
  const tab = getActiveTab();
  if (!tab) return;
  const targetId = tab.targetId;
  const credentials = { ...tab.credentials };
  const connected = tab.connected;
  const title = tab.title;

  tab.pane.remove();
  try { tab.term.dispose(); } catch {}

  const pane = document.createElement('div');
  pane.className = `terminal-pane ${tab.id === activeTabId ? 'active' : ''}`;
  const host = document.createElement('div');
  host.className = 'terminal-host';
  pane.appendChild(host);
  els.terminalStack.appendChild(pane);

  const { term, fitAddon } = createTerminalForPane(host, els.scrollbackSelect.value);
  Object.assign(tab, {
    pane,
    host,
    term,
    fitAddon,
    targetId,
    credentials,
    title,
    scrollback: Number(els.scrollbackSelect.value),
    connected: false,
  });

  term.onData((data) => {
    if (tab.socket && tab.socket.readyState === WebSocket.OPEN) {
      tab.socket.send(JSON.stringify({ type: 'input', data }));
    }
  });

  term.onResize(({ cols, rows }) => {
    if (tab.socket && tab.socket.readyState === WebSocket.OPEN) {
      tab.socket.send(JSON.stringify({ type: 'resize', cols, rows }));
    }
  });

  renderTabs();
  if (connected) connectActiveTab('restart');
}

async function copyActiveTab() {
  const tab = getActiveTab();
  if (!tab) return;
  const text = extractTerminalText(tab);
  try {
    await navigator.clipboard.writeText(text);
    setStatus(`${tab.title} · copiado al portapapeles`);
  } catch {
    setStatus(`${tab.title} · no se pudo copiar automáticamente`);
  }
}

function extractTerminalText(tab) {
  return Array.from({ length: tab.term.buffer.active.length }, (_, i) => tab.term.buffer.active.getLine(i)?.translateToString(true) || '').join('\n');
}

function saveActiveTabOutput() {
  const tab = getActiveTab();
  if (!tab) return;
  const target = getTargetById(tab.targetId);
  const safeTitle = (tab.title || 'terminal').replace(/[^a-z0-9-_]+/gi, '_').replace(/^_+|_+$/g, '') || 'terminal';
  const date = new Date().toISOString().replace(/[:.]/g, '-');
  const text = extractTerminalText(tab);
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${safeTitle}_${target?.id || 'target'}_${date}.txt`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
  setStatus(`${tab.title} · salida guardada en fichero local`);
}

function connectActiveTab(type = 'start') {
  const tab = updateActiveTabState();
  if (!tab) return;
  openSocketForTab(tab, type);
}

async function handleLogin(event) {
  event.preventDefault();
  els.loginMessage.textContent = '';
  try {
    const data = await fetchJson('/api/auth/login', { method: 'POST', body: JSON.stringify({ password: els.loginPassword.value }) });
    authStatus.authenticated = !!data.authenticated;
    ensureAuthenticatedUi();
    els.loginPassword.value = '';
    setStatus('Login correcto.');
  } catch (error) {
    els.loginMessage.textContent = error.message;
  }
}

async function handleLogout() {
  await fetchJson('/api/auth/logout', { method: 'POST', body: JSON.stringify({}) });
  authStatus.authenticated = false;
  ensureAuthenticatedUi();
  for (const tab of tabs) {
    try { tab.socket?.close(); } catch {}
    tab.connected = false;
    tab.lastStatus = 'Sesión cerrada por logout';
  }
  renderTabs();
  setStatus('Sesión cerrada.');
}

function createNewTabFromControls() {
  const title = (els.newTabName.value || '').trim() || `Pestaña ${tabs.length + 1}`;
  const targetId = els.newTabTargetSelect.value || els.defaultTargetSelect.value || runtimeConfig.targets[0]?.id || '';
  const scrollback = Number(els.defaultScrollbackSelect.value || 20000);
  const tab = createTab({ title, targetId, scrollback });
  els.newTabName.value = '';
  setStatus(`${tab.title} · creada.`);
}

function bindEvents() {
  els.loginForm.addEventListener('submit', handleLogin);
  els.logoutBtn.addEventListener('click', handleLogout);
  els.targetSelect.addEventListener('change', () => {
    updateActiveTabState();
    renderCredentialFields();
  });
  els.scrollbackSelect.addEventListener('change', () => {
    updateActiveTabState();
    applyScrollbackToActiveTab();
  });
  els.defaultTargetSelect.addEventListener('change', () => {
    if (!els.newTabTargetSelect.dataset.touched) els.newTabTargetSelect.value = els.defaultTargetSelect.value;
  });
  els.newTabTargetSelect.addEventListener('change', () => { els.newTabTargetSelect.dataset.touched = '1'; });
  els.connectBtn.addEventListener('click', () => connectActiveTab('start'));
  els.restartBtn.addEventListener('click', () => connectActiveTab('restart'));
  els.clearBtn.addEventListener('click', () => { const tab = getActiveTab(); tab?.term.clear(); tab?.term.focus(); });
  els.copyBtn.addEventListener('click', copyActiveTab);
  els.saveBtn.addEventListener('click', saveActiveTabOutput);
  els.newTabBtn.addEventListener('click', createNewTabFromControls);
  window.addEventListener('resize', () => {
    const tab = getActiveTab();
    if (!tab) return;
    tab.fitAddon.fit();
    if (tab.socket && tab.socket.readyState === WebSocket.OPEN) {
      tab.socket.send(JSON.stringify({ type: 'resize', cols: tab.term.cols, rows: tab.term.rows }));
    }
  });
}

async function loadBootstrap() {
  runtimeConfig = await fetchJson('/api/config');
  authStatus = await fetchJson('/api/auth/status');
  els.appSubtitle.textContent = runtimeConfig.auth.login_required ? 'Terminal web con tabs, targets locales y remotos y login' : 'Terminal web con tabs y targets locales y remotos';
  ensureAuthenticatedUi();
  fillSelect(els.defaultTargetSelect, runtimeConfig.targets[0]?.id || '');
  fillSelect(els.newTabTargetSelect, runtimeConfig.targets[0]?.id || '');
  fillSelect(els.targetSelect, runtimeConfig.targets[0]?.id || '');
  buildGlobalInfo();
  if (!tabs.length) {
    createTab({ title: 'Pestaña 1', targetId: runtimeConfig.targets[0]?.id || '', scrollback: Number(els.defaultScrollbackSelect.value) });
  }
  renderCredentialFields();
  syncActiveTabToControls();
}

loadBootstrap().then(bindEvents).catch((error) => {
  console.error(error);
  setStatus(`Error de arranque: ${error.message}`);
});
})();
