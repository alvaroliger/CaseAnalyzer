'use strict';
const CSRF        = document.querySelector('meta[name="csrf-token"]').content;
const BACKEND_URL = window.BACKEND_URL || 'http://localhost:8001';

// ─── Estado global ────────────────────────────────────────────────────────────
let D = null;          // datos del análisis completo
let _fileId  = null;
let _imgOffset = 0;

// Cache de listas filtradas
let _allFiles = [], _delFiles = [], _history = [], _suspicious = [], _lnk = [], _pf = [];
let _strTabActive = 'urls';
let _sortFiles = {col: 'name', dir: 1};
let _sortHist  = {col: 'time', dir: -1};

// ─── Paginación ──────────────────────────────────────────────────────────────
const _PAGE_SIZE  = 300;
let _filesPage    = 0;
let _delPage      = 0;
let _currentFiles = [];
let _currentDel   = [];

// ─── Utilidades ───────────────────────────────────────────────────────────────
function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function el(id) { return document.getElementById(id); }
function setText(id, v) { const e = el(id); if (e) e.textContent = v ?? '—'; }
function fmtSize(b) {
  const n = parseInt(b) || 0;
  if (!n) return '0 B';
  const u = ['B','KB','MB','GB','TB'], i = Math.floor(Math.log2(n) / 10);
  return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
}
function fmtTs(ts) {
  if (!ts || ts === '—' || ts === '0') return '—';
  // Unix timestamp
  if (/^\d{9,11}$/.test(String(ts))) {
    return new Date(parseInt(ts) * 1000).toISOString().replace('T', ' ').slice(0, 19);
  }
  return String(ts).slice(0, 19);
}

function toast(msg, type = 'info', dur = 3500) {
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span>${type === 'ok' ? '✓' : type === 'err' ? '✖' : 'ℹ'}</span><span>${esc(msg)}</span>`;
  el('toasts').appendChild(t);
  setTimeout(() => t.remove(), dur);
}

// ─── Navegación ───────────────────────────────────────────────────────────────
const SECTION_MAP = {
  'upload':'s-upload','overview':'s-overview','files':'s-files','deleted':'s-deleted',
  'filetypes':'s-filetypes','history':'s-history','downloads':'s-downloads',
  'searches':'s-searches','lnk':'s-lnk','prefetch':'s-prefetch','registry':'s-registry',
  'users':'s-users','suspicious':'s-suspicious','strings':'s-strings',
  'timeline':'s-timeline','hex':'s-hex','inode':'s-inode','partitions':'s-partitions',
  'report':'s-report',
  'recycle':'s-recycle','startup':'s-startup','events':'s-events',
  'email':'s-email','network':'s-network','usb':'s-usb'
};
const TI_MAP = {
  'overview':'ti-overview','partitions':'ti-partitions','files':'ti-files',
  'deleted':'ti-deleted','filetypes':'ti-filetypes','history':'ti-history',
  'downloads':'ti-downloads','searches':'ti-searches','lnk':'ti-lnk',
  'prefetch':'ti-prefetch','registry':'ti-registry','users':'ti-users',
  'suspicious':'ti-suspicious','strings':'ti-urls','timeline':'ti-timeline',
  'hex':'ti-hex','inode':'ti-inode','report':'ti-report',
  'recycle':'ti-recycle','startup':'ti-startup','events':'ti-events',
  'email':'ti-email','network':'ti-network','usb':'ti-usb'
};

function nav(section, strTab) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.tree-item').forEach(i => i.classList.remove('active'));
  const sid = SECTION_MAP[section];
  if (sid) el(sid)?.classList.add('active');
  const tid = TI_MAP[section];
  if (tid) el(tid)?.classList.add('active');
  if (section === 'strings' && strTab) switchStrTab(strTab);
  if (section === 'report' && D) generateReport();
}

function toggleGroup(id) {
  el(id).classList.toggle('open');
}

// ─── Health check ─────────────────────────────────────────────────────────────
async function refreshHealth() {
  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), 6000);
    const r    = await fetch('/api/health', { signal: ctrl.signal });
    clearTimeout(tid);
    const d = await r.json();
    const ok = d.status === 'ok';
    el('health-dot').className = ok ? 'ok' : '';
    el('health-txt').textContent = ok ? `${d.backend} · ${d.platform}` : 'desconectado';
    if (d.capabilities) {
      setDot('bc-pytsk3', d.capabilities.pytsk3);
      setDot('bc-tsk',    d.capabilities.tsk_binaries);
      setDot('bc-wsl',    d.capabilities.wsl);
    }
  } catch {
    el('health-dot').className = '';
    el('health-txt').textContent = 'desconectado';
  }
}
function setDot(id, ok) {
  const e = el(id); if (e) e.className = 'bc-dot ' + (ok ? 'ok' : 'no');
}
refreshHealth();
setInterval(refreshHealth, 15000);

// ─── Upload ───────────────────────────────────────────────────────────────────
el('file-input').addEventListener('change', e => { if (e.target.files.length) upload(e.target.files); });

async function upload(fileList) {
  const files = Array.from(fileList).sort((a, b) => a.name.localeCompare(b.name));
  const file  = files[0]; // primario (para referencias de nombre/tamaño)
  const STEPS = [
    {p:8,  t:'Subiendo imagen...'},
    {p:22, t:'Detectando particiones...'},
    {p:40, t:'Listando ficheros...'},
    {p:58, t:'Buscando eliminados...'},
    {p:72, t:'Extrayendo artefactos web...'},
    {p:82, t:'Analizando actividad reciente...'},
    {p:90, t:'Extrayendo strings...'},
    {p:95, t:'Finalizando análisis...'},
  ];

  el('drop-zone').style.display = 'none';
  const pb = el('progress-box');
  pb.style.display = 'block';
  const bar = el('pb-bar'), title = el('pb-title'), pct = el('pb-pct'), steps = el('pb-steps');

  function renderSteps(active) {
    steps.innerHTML = STEPS.map((s, i) => {
      const cls = i < active ? 'done' : i === active ? 'active' : '';
      return `<div class="pb-step ${cls}"><span class="pb-step-dot"></span>${esc(s.t)}</div>`;
    }).join('');
  }
  renderSteps(0);

  let si = 0, dots = 0;
  const tick = setInterval(() => {
    if (si < STEPS.length - 1) {
      const s = STEPS[si];
      bar.style.width = s.p + '%';
      title.textContent = s.t;
      pct.textContent = s.p + '%';
      renderSteps(si);
      si++;
    } else {
      dots = (dots + 1) % 4;
      title.textContent = 'Procesando' + '.'.repeat(dots || 1);
      const wave = 95 + Math.round(3 * Math.abs(Math.sin(Date.now() / 1800)));
      bar.style.width = wave + '%';
      pct.textContent = wave + '%';
    }
  }, 900);

  window._lastFileId = null;

  try {
    const fd = new FormData();
    files.forEach(f => fd.append('files', f));
    // Subida directa al backend Python (sin pasar por PHP) → sin límite de tamaño
    let res;
    try {
      res = await fetch(`${BACKEND_URL}/analyze`, {
        method: 'POST',
        body: fd,
      });
    } catch (netErr) {
      throw new Error(`No se puede conectar al backend Python (${BACKEND_URL}). ¿Está arrancado?`);
    }
    clearInterval(tick);

    const body = await res.json().catch(() => null);

    // Guardar file_id aunque haya error, para poder recuperar el log
    if (body?.file_id) window._lastFileId = body.file_id;

    if (!res.ok) {
      const msg = body?.error || body?.detail || `Error HTTP ${res.status}`;
      throw new Error(msg);
    }

    if (!body) throw new Error('Respuesta vacía del servidor');

    // Si el backend devuelve {error:...} con 200, mostrarlo igualmente
    if (body.error && !body.file_id) {
      throw new Error('Backend error: ' + body.error.split('\n')[0]);
    }

    bar.style.width = '100%';
    title.textContent = '✓ Análisis completo';
    pct.textContent = '100%';
    renderSteps(STEPS.length);

    D = body;
    _fileId    = D.file_id;
    window._lastFileId = D.file_id;
    _imgOffset = D.detected_offset || 0;

    // Avisar si el backend no pudo analizar el FS
    if (D.backend === 'none' || D.backend === 'error') {
      toast(
        'Sin backend forense: solo hashes y strings disponibles. ' +
        'Para análisis completo: en WSL ejecuta → sudo apt install -y sleuthkit',
        'info', 10000
      );
    } else if (!D.total_files && !D.total_deleted) {
      toast(
        'El análisis completó pero no encontró ficheros en el filesystem. ' +
        'Revisa "img_stat" en el Resumen para ver el error del backend.',
        'info', 10000
      );
    }

    populate(D);
    el('export-btn').disabled = false;
    el('new-btn').style.display = '';
    setTimeout(() => nav('overview'), 600);

  } catch (err) {
    clearInterval(tick);
    bar.style.background = 'var(--red)';
    const msg = err.name === 'AbortError'
      ? 'Tiempo agotado (>640s). Backend no responde — revisa la consola Python.'
      : err.message;
    title.textContent = '✖ ' + msg;
    pct.textContent = '';

    // Intentar obtener el log si tenemos file_id
    const logFileId = window._lastFileId;
    let logHtml = '';
    if (logFileId) {
      try {
        const lr = await fetch(`/api/logs/${logFileId}`);
        if (lr.ok) {
          const ld = await lr.json();
          logHtml = `<pre style="margin-top:12px;background:#0d1117;border:1px solid #f85149;border-radius:6px;padding:10px;font-size:11px;color:#e6edf3;max-height:220px;overflow-y:auto;text-align:left;white-space:pre-wrap">${esc(ld.log)}</pre>`;
        }
      } catch {}
    }

    steps.innerHTML = `<div style="color:var(--red);font-size:12px;word-break:break-word">${esc(msg)}</div>${logHtml}`;
    toast(msg, 'err', 8000);
    setTimeout(() => {
      pb.style.display = 'none';
      el('drop-zone').style.display = '';
      bar.style.cssText = '';
      steps.innerHTML = '';
    }, 12000);
  }
}

function newCase() {
  D = null; _fileId = null;
  el('export-btn').disabled = true;
  el('new-btn').style.display = 'none';
  el('drop-zone').style.display = '';
  el('progress-box').style.display = 'none';
  el('tb-case').textContent = 'Sin caso abierto';
  el('sc-name').textContent = '—';
  el('sc-meta').textContent = '—';
  // reset badges
  ['files','deleted','history','downloads','searches','lnk','prefetch',
   'registry','users','suspicious','urls','emails','ips','paths',
   'recycle','startup','events','email','network','usb'].forEach(k => {
    const b = el('bd-' + k); if (b) { b.textContent = '0'; b.parentElement?.classList.remove('has-data','has-warning'); }
  });
  nav('upload');
}

// ─── Populate ─────────────────────────────────────────────────────────────────
function populate(d) {
  // Topbar & sidebar case info
  const sizeStr = fmtSize(d.file_size);
  el('tb-case').innerHTML = `<strong>${esc(d.filename)}</strong> · ${sizeStr}`;
  el('sc-name').textContent = d.filename || '—';
  const os = d.os_info || {};
  el('sc-meta').textContent = `${os.os || '—'} · ${sizeStr}`;

  // Overview stats
  setText('ov-total',     d.total_files ?? 0);
  setText('ov-del',       d.total_deleted ?? 0);
  setText('ov-suspicious',(d.suspicious_files || []).length);
  setText('ov-users-c',   (d.users || []).length);
  setText('ov-history-c', (d.browser_history?.visits || []).length);
  setText('ov-lnk-c',     ((d.recent_activity?.lnk || []).length + (d.recent_activity?.prefetch || []).length));
  setText('ov-urls',      (d.strings?.urls || []).length);
  setText('ov-emails',    (d.strings?.emails || []).length);
  setText('ov-events',    (d.event_logs || []).length);
  setText('ov-startup',   (d.startup_items || []).length);
  setText('ov-recycle',   (d.recycle_bin || []).length);

  // Overview kvs
  setText('ov-filename',  d.filename);
  setText('kv-filename',  d.filename);
  setText('kv-size',      sizeStr);
  setText('kv-imgtype',   d.image_type?.type || '—');
  setText('kv-entropy',   d.entropy !== undefined ? d.entropy + ' bits/byte' : '—');
  setText('kv-backend',   d.backend_info?.active || '—');
  const osTag = el('ov-os-tag');
  if (osTag) {
    osTag.textContent = (os.os || '—') + (os.version ? ' ' + os.version : '') + ' (' + (os.confidence || '?') + ')';
    osTag.className = 'tag ' + (os.os === 'Windows' ? 'tag-blue' : os.os === 'Linux' ? 'tag-green' : 'tag-muted');
  }
  const osLine = (os.os || '—') + (os.version ? ' ' + os.version : '') + ' (confianza: ' + (os.confidence || '?') + ')';
  setText('kv-os',      osLine);
  setText('ov-subtitle', `Backend: ${d.backend_info?.active || '—'} · ${d.platform || '—'} · ${new Date().toLocaleString()}`);

  const h = d.hashes || {};
  setText('kv-md5',       h.md5  || '—');
  setText('kv-sha1',      h.sha1 || '—');
  setText('kv-sha256',    h.sha256 || '—');
  setText('kv-hash-note', h.note || '—');

  setText('kv-fsstat',  d.image_info?.fsstat   || '(sin datos)');
  setText('kv-imgstat', d.image_info?.img_stat || '(sin datos)');
  setText('part-mmls',  d.image_info?.partitions || '(sin tabla)');

  if (d.backend_info) {
    setDot('bc-pytsk3', d.backend_info.pytsk3);
    setDot('bc-tsk',    d.backend_info.tsk_bin);
    setDot('bc-wsl',    d.backend_info.wsl);
    setDot('bc-7zip',   d.backend_info['7zip']);
  }

  // Banner de error cuando el FS está vacío
  const warnBanner = el('ov-warn-banner');
  if (warnBanner) {
    const imgStat = d.image_info?.img_stat || '';
    const hasFiles = (d.total_files || 0) > 0 || (d.total_deleted || 0) > 0;
    if (!hasFiles && (d.backend === 'none' || d.backend === 'error' || imgStat.startsWith('Error'))) {
      const backendInfo = d.backend_info || {};
      warnBanner.innerHTML = `<strong>⚠ El análisis no pudo leer el filesystem.</strong><br>
        Backend activo: <code>${esc(d.backend || '?')}</code> · pytsk3: ${backendInfo.pytsk3 ? '✓' : '✗'} · WSL: ${backendInfo.wsl ? '✓' : '✗'}<br>
        ${imgStat ? `<em>${esc(imgStat.slice(0, 300))}</em><br>` : ''}
        Hashes calculados correctamente — solo el listado de ficheros falló.`;
      warnBanner.style.display = 'block';
    } else {
      warnBanner.style.display = 'none';
    }
  }

  // Cache data
  _allFiles  = d.files || [];
  _delFiles  = d.deleted || [];
  _history   = d.browser_history?.visits || [];
  _suspicious = d.suspicious_files || [];
  _lnk       = d.recent_activity?.lnk || [];
  _pf        = d.recent_activity?.prefetch || [];

  // Render sections
  renderFiles(_allFiles);
  renderDeleted(_delFiles);
  renderFileTypes(d.file_types || {});
  renderHistory(_history, d.browser_history?.downloads || []);
  renderDownloads(d.browser_history?.downloads || []);
  renderSearches(d.browser_history?.searches || []);
  renderLnk(_lnk);
  renderPrefetch(_pf);
  renderRegistry(d.recent_activity?.registry_hives || []);
  renderUsers(d.users || []);
  renderSuspicious(_suspicious);
  renderStrings(d.strings || {});
  buildTimeline(_allFiles);

  // Update sidebar badges
  setBadge('bd-files',     d.total_files, 'ti-files');
  setBadge('bd-deleted',   d.total_deleted, 'ti-deleted', true);
  setBadge('bd-history',   _history.length, 'ti-history');
  setBadge('bd-downloads', (d.browser_history?.downloads || []).length, 'ti-downloads');
  setBadge('bd-searches',  (d.browser_history?.searches || []).length, 'ti-searches');
  setBadge('bd-lnk',       _lnk.length, 'ti-lnk');
  setBadge('bd-prefetch',  _pf.length, 'ti-prefetch');
  setBadge('bd-registry',  (d.recent_activity?.registry_hives || []).length, 'ti-registry');
  setBadge('bd-users',     (d.users || []).length, 'ti-users');
  setBadge('bd-suspicious',(d.suspicious_files || []).length, 'ti-suspicious', true);
  setBadge('bd-urls',      (d.strings?.urls || []).length, 'ti-urls');
  setBadge('bd-emails',    (d.strings?.emails || []).length, 'ti-emails');
  setBadge('bd-ips',       (d.strings?.ips || []).length, 'ti-ips');
  setBadge('bd-paths',     (d.strings?.paths || []).length, 'ti-paths');

  // Nuevos artefactos forenses
  renderRecycleBin(d.recycle_bin || []);
  renderStartupItems(d.startup_items || []);
  renderEventLogs(d.event_logs || []);
  renderEmailFiles(d.email_files || []);
  renderNetworkArtifacts(d.network_artifacts || []);
  renderUsbTraces(d.usb_traces || []);

  setBadge('bd-recycle',  (d.recycle_bin || []).length,     'ti-recycle');
  setBadge('bd-startup',  (d.startup_items || []).length,   'ti-startup');
  setBadge('bd-events',   (d.event_logs || []).length,      'ti-events');
  setBadge('bd-email',    (d.email_files || []).length,     'ti-email');
  setBadge('bd-network',  (d.network_artifacts || []).length, 'ti-network');
  setBadge('bd-usb',      (d.usb_traces || []).length,      'ti-usb');

  // Imágenes adicionales (imágenes separadas subidas junto a la primaria)
  const addImgs = d.additional_images || [];
  const addBanner = el('additional-images-banner');
  if (addBanner) {
    if (addImgs.length > 0) {
      const rows = addImgs.map(img => {
        const sz  = fmtSize(img.file_size || 0);
        const os2 = img.os_info?.os || '?';
        return `<div class="add-img-row">
          <span class="add-img-name">${esc(img.filename)}</span>
          <span class="add-img-meta">${img.total_files ?? 0} ficheros · ${img.total_deleted ?? 0} eliminados · ${os2} · ${sz}</span>
        </div>`;
      }).join('');
      addBanner.innerHTML = `<div class="add-img-header">
        <span>Imágenes adicionales analizadas (${addImgs.length})</span>
        <button onclick="this.closest('#additional-images-banner').style.display='none'" class="add-img-close">✕</button>
      </div>${rows}`;
      addBanner.style.display = 'block';
    } else {
      addBanner.style.display = 'none';
    }
  }
}

function setBadge(bdId, count, tiId, warn = false) {
  const b = el(bdId);
  if (!b) return;
  b.textContent = count || 0;
  const ti = el(tiId);
  if (!ti) return;
  ti.classList.remove('has-data', 'has-warning');
  if (count > 0) ti.classList.add(warn ? 'has-warning' : 'has-data');
}

// ─── Files table ──────────────────────────────────────────────────────────────
function _filesRowHtml(f) {
  const isDel = f.deleted, isDir = f.type === 'dir';
  const badge = isDel ? '<span class="badge b-del">DEL</span>'
              : isDir ? '<span class="badge b-dir">DIR</span>'
                      : '<span class="badge b-file">FILE</span>';
  const style = isDel ? 'color:var(--red)' : isDir ? 'color:var(--green)' : '';
  return `<tr data-type="${isDel?'deleted':esc(f.type||'')}" data-name="${esc((f.name||'').toLowerCase())}" data-inode="${esc(f.inode||'')}">
    <td>${badge}</td>
    <td style="${style};max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.name)}">${esc(f.name||f.raw||'—')}</td>
    <td style="color:var(--muted);font-family:monospace">${esc(f.inode||'—')}</td>
    <td style="color:var(--muted)">${fmtSize(f.size)}</td>
    <td style="color:var(--muted);font-family:monospace">${esc(fmtTs(f.mtime))}</td>
  </tr>`;
}

function renderFiles(files, append = false) {
  _currentFiles = files;
  if (!append) _filesPage = 0;
  const tbody = el('files-body');
  const total = files.length;
  setText('files-count', total + ' entradas');

  if (!total) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><div class="empty-text">Sin ficheros</div></div></td></tr>';
    return;
  }

  const start = _filesPage * _PAGE_SIZE;
  const slice = files.slice(start, start + _PAGE_SIZE);
  const hasMore = total > start + _PAGE_SIZE;
  const remaining = total - start - slice.length;
  const moreRow = hasMore
    ? `<tr class="load-more-row"><td colspan="5"><button class="load-more-btn" onclick="loadMoreFiles()">Mostrar ${Math.min(remaining, _PAGE_SIZE)} más (${remaining} restantes)</button></td></tr>`
    : '';
  const html = slice.map(_filesRowHtml).join('') + moreRow;

  if (append) {
    const existing = tbody.querySelector('.load-more-row');
    if (existing) existing.remove();
    tbody.insertAdjacentHTML('beforeend', html);
  } else {
    tbody.innerHTML = html;
  }

  tbody.querySelectorAll('tr[data-inode]').forEach(row => {
    row.style.cursor = 'pointer';
    row.addEventListener('click', () => {
      const inode = row.dataset.inode;
      if (inode && inode !== '—') { el('inode-input').value = inode; nav('inode'); inspectInode(); }
    });
  });
}

function loadMoreFiles() { _filesPage++; renderFiles(_currentFiles, true); }


function filterFiles() {
  const q  = el('files-search').value.toLowerCase();
  const ft = el('files-filter').value;
  const filtered = _allFiles.filter(f => {
    const name = (f.name || '').toLowerCase();
    const matchQ = !q || name.includes(q) || (f.inode || '').includes(q);
    const type   = f.deleted ? 'deleted' : (f.type || 'file');
    const matchF = !ft || type === ft;
    return matchQ && matchF;
  });
  renderFiles(filtered);
}

function sortFiles(col) {
  if (_sortFiles.col === col) _sortFiles.dir *= -1;
  else { _sortFiles.col = col; _sortFiles.dir = 1; }
  _allFiles.sort((a, b) => {
    let va = a[col] || '', vb = b[col] || '';
    if (col === 'size') { va = parseInt(va) || 0; vb = parseInt(vb) || 0; }
    return va < vb ? -_sortFiles.dir : va > vb ? _sortFiles.dir : 0;
  });
  filterFiles();
}

// ─── Deleted ──────────────────────────────────────────────────────────────────
function _delRowHtml(f) {
  const name = f.name || f.raw || '—';
  return `<tr>
    <td style="color:var(--red);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:220px" title="${esc(name)}">${esc(name)}</td>
    <td style="font-family:monospace;color:var(--muted)">${esc(f.inode || '—')}</td>
    <td style="color:var(--muted2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:300px" title="${esc(f.raw||'')}">${esc(f.raw || '—')}</td>
  </tr>`;
}

function renderDeleted(files, append = false) {
  _currentDel = files;
  if (!append) _delPage = 0;
  const tbody = el('del-body');
  const total = files.length;
  setText('del-count', total + ' ficheros');

  if (!total) {
    tbody.innerHTML = '<tr><td colspan="3"><div class="empty"><div class="empty-text">No se detectaron ficheros eliminados</div></div></td></tr>';
    return;
  }

  const start = _delPage * _PAGE_SIZE;
  const slice = files.slice(start, start + _PAGE_SIZE);
  const hasMore = total > start + _PAGE_SIZE;
  const remaining = total - start - slice.length;
  const moreRow = hasMore
    ? `<tr class="load-more-row"><td colspan="3"><button class="load-more-btn" onclick="loadMoreDel()">Mostrar ${Math.min(remaining, _PAGE_SIZE)} más (${remaining} restantes)</button></td></tr>`
    : '';
  const html = slice.map(_delRowHtml).join('') + moreRow;

  if (append) {
    const existing = tbody.querySelector('.load-more-row');
    if (existing) existing.remove();
    tbody.insertAdjacentHTML('beforeend', html);
  } else {
    tbody.innerHTML = html;
  }
}

function loadMoreDel() { _delPage++; renderDeleted(_currentDel, true); }


function filterDeleted() {
  const q = el('del-search').value.toLowerCase();
  renderDeleted(q ? _delFiles.filter(f => (f.name || f.raw || '').toLowerCase().includes(q)) : _delFiles);
}

// ─── File types ───────────────────────────────────────────────────────────────
function renderFileTypes(types) {
  const total = Object.values(types).reduce((s, v) => s + (v.count || 0), 0) || 1;
  const COLORS = ['var(--blue)','var(--green)','var(--purple)','var(--orange)',
                  'var(--cyan)','var(--red)','#ff9f43','#a29bfe','#fd79a8'];
  const sorted = Object.entries(types).sort((a, b) => b[1].count - a[1].count);
  el('ft-grid').innerHTML = sorted.map(([cat, info], i) => {
    const pct = Math.round(info.count / total * 100);
    const color = COLORS[i % COLORS.length];
    const topExts = Object.entries(info.extensions || {})
      .sort((a,b) => b[1]-a[1]).slice(0, 5)
      .map(([e, c]) => `<span class="ft-ext">${esc(e)} (${c})</span>`).join('');
    return `<div class="ft-card">
      <h3>${esc(cat)}</h3>
      <div class="ft-count" style="color:${color}">${info.count}</div>
      <div class="ft-bar-track"><div class="ft-bar" style="width:${pct}%;background:${color}"></div></div>
      <div class="ft-exts">${topExts}</div>
    </div>`;
  }).join('');
}

// ─── Browser history ─────────────────────────────────────────────────────────
function renderHistory(visits, downloads) {
  setText('hist-count', visits.length + ' visitas');

  // Populate browser filter
  const browsers = [...new Set(visits.map(v => v.browser).filter(Boolean))];
  const sel = el('hist-browser');
  const cur = sel.value;
  sel.innerHTML = '<option value="">Todos los navegadores</option>' +
    browsers.map(b => `<option value="${esc(b)}" ${b===cur?'selected':''}>${esc(b)}</option>`).join('');

  // Note about browser DBs found
  const note = el('hist-note');
  if (visits.length === 0 && D?.browser_dbs?.dbs?.length > 0) {
    note.className = 'warn-note';
    const dbList = D.browser_dbs.dbs.filter(d => d.type === 'history')
      .map(d => `${d.browser} (${fmtSize(d.size)})`).join(', ');
    note.textContent = `Se encontraron bases de datos de navegadores: ${dbList} — pero no se pudo extraer el historial (requiere pytsk3).`;
  } else if (visits.length > 0) {
    note.className = 'info-note';
    note.textContent = `Historial extraído de ${browsers.join(', ')}.`;
  } else {
    note.textContent = '';
    note.className = '';
  }

  filterHistory();
}

function filterHistory() {
  const q  = el('hist-search').value.toLowerCase();
  const br = el('hist-browser').value;
  const tbody = el('hist-body');
  const filtered = _history.filter(v => {
    const matchQ = !q || (v.url || '').toLowerCase().includes(q) || (v.title || '').toLowerCase().includes(q);
    const matchB = !br || v.browser === br;
    return matchQ && matchB;
  });
  setText('hist-count', filtered.length + ' visitas');
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><div class="empty-text">Sin historial de navegación</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = filtered.map(v => `<tr>
    <td><span class="tag tag-blue">${esc(v.browser||'?')}</span></td>
    <td style="font-family:monospace;color:var(--muted);white-space:nowrap">${esc(v.time||'—')}</td>
    <td style="max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
      <a href="${esc(v.url)}" target="_blank" rel="noopener noreferrer" title="${esc(v.url)}">${esc(v.url||'—')}</a></td>
    <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted)">${esc(v.title||'—')}</td>
    <td style="color:var(--muted);text-align:right">${v.count||1}</td>
  </tr>`).join('');
}

function sortHistory(col) {
  if (_sortHist.col === col) _sortHist.dir *= -1;
  else { _sortHist.col = col; _sortHist.dir = 1; }
  _history.sort((a, b) => {
    const va = a[col] || '', vb = b[col] || '';
    return va < vb ? -_sortHist.dir : va > vb ? _sortHist.dir : 0;
  });
  filterHistory();
}

function renderDownloads(downloads) {
  const tbody = el('dl-body');
  setText('dl-count', downloads.length + ' descargas');
  if (!downloads.length) {
    tbody.innerHTML = '<tr><td colspan="3"><div class="empty"><div class="empty-text">Sin descargas</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = downloads.map(d => `<tr>
    <td style="font-family:monospace;color:var(--muted);white-space:nowrap">${esc(d.time||'—')}</td>
    <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(d.path)}">${esc(d.path||'—')}</td>
    <td style="color:var(--muted)">${fmtSize(d.size)}</td>
  </tr>`).join('');
}

function renderSearches(searches) {
  const grid = el('srch-grid');
  setText('srch-count', searches.length + ' términos');
  if (!searches.length) {
    grid.innerHTML = '<div class="empty"><div class="empty-text">Sin búsquedas web registradas</div></div>';
    return;
  }
  grid.innerHTML = searches.map(s => `<div class="str-item" onclick="copyStr(this,'${esc(s).replace(/'/g,"\\'")}'">${esc(s)}</div>`).join('');
}

// ─── LNK ─────────────────────────────────────────────────────────────────────
function renderLnk(lnks) {
  const tbody = el('lnk-body');
  setText('lnk-count', lnks.length + ' ficheros');
  if (!lnks.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><div class="empty-text">Sin ficheros LNK</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = lnks.map(f => `<tr>
    <td>${f.deleted ? '<span class="badge b-del">DEL</span>' : '<span class="badge b-lnk">LNK</span>'}</td>
    <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.path)}">${esc(f.name||'—')}</td>
    <td style="font-family:monospace;color:var(--muted);white-space:nowrap">${esc(fmtTs(f.mtime))}</td>
    <td style="font-family:monospace;color:var(--muted)">${esc(f.inode||'—')}</td>
    <td>
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openHex('${esc(f.inode)}')">Hex</button>` : ''}
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openInode('${esc(f.inode)}')">Meta</button>` : ''}
    </td>
  </tr>`).join('');
}

function filterLnk() {
  const q = el('lnk-search').value.toLowerCase();
  renderLnk(q ? _lnk.filter(f => (f.name||'').toLowerCase().includes(q)) : _lnk);
}

function sortLnk(col) {
  _lnk.sort((a,b) => String(a[col]||'').localeCompare(String(b[col]||'')));
  renderLnk(_lnk);
}

// ─── Prefetch ─────────────────────────────────────────────────────────────────
function renderPrefetch(pfs) {
  const tbody = el('pf-body');
  setText('pf-count', pfs.length + ' ficheros');
  if (!pfs.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><div class="empty-text">Sin ficheros Prefetch</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = pfs.map(f => `<tr>
    <td style="font-weight:600;color:var(--orange)">${esc(f.exe||'—')}</td>
    <td style="font-family:monospace;color:var(--muted);white-space:nowrap">${esc(fmtTs(f.mtime))}</td>
    <td style="color:var(--muted2);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.path)}">${esc(f.name||'—')}</td>
    <td style="font-family:monospace;color:var(--muted)">${esc(f.inode||'—')}</td>
    <td>
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openHex('${esc(f.inode)}')">Hex</button>` : ''}
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openInode('${esc(f.inode)}')">Meta</button>` : ''}
    </td>
  </tr>`).join('');
}

function sortPf(col) {
  _pf.sort((a,b) => String(a[col]||'').localeCompare(String(b[col]||'')));
  renderPrefetch(_pf);
}

// ─── Registry ─────────────────────────────────────────────────────────────────
function renderRegistry(hives) {
  const tbody = el('reg-body');
  if (!hives.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty"><div class="empty-text">Sin hives de registro detectados</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = hives.map(h => `<tr>
    <td style="font-weight:600;color:var(--purple)">${esc(h.name||'—')}</td>
    <td style="color:var(--muted2);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(h.path)}">${esc(h.path||'—')}</td>
    <td style="color:var(--muted)">${fmtSize(h.size)}</td>
    <td style="font-family:monospace;color:var(--muted)">${esc(h.inode||'—')}</td>
    <td>
      ${h.inode && h.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openHex('${esc(h.inode)}')">Hex</button>` : ''}
      ${h.inode && h.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openInode('${esc(h.inode)}')">Meta</button>` : ''}
    </td>
  </tr>`).join('');
}

// ─── Users ────────────────────────────────────────────────────────────────────
function renderUsers(users) {
  const grid = el('user-grid');
  if (!users.length) {
    grid.innerHTML = '<div class="empty"><div class="empty-text">No se detectaron usuarios</div></div>';
    return;
  }
  grid.innerHTML = users.map(u => {
    const initial = (u.name || '?')[0].toUpperCase();
    const osTag   = u.os === 'Windows' ? 'tag-blue' : 'tag-green';
    return `<div class="user-card">
      <div class="user-avatar">${esc(initial)}</div>
      <div class="user-name">${esc(u.name)}</div>
      <div class="user-meta">
        <span class="tag ${osTag}">${esc(u.os)}</span>
        <span style="margin-left:6px">${u.files} ficheros</span>
      </div>
      ${u.last_seen && u.last_seen !== '—' ?
        `<div class="user-meta" style="margin-top:4px">Último: ${esc(fmtTs(u.last_seen))}</div>` : ''}
    </div>`;
  }).join('');
}

// ─── Suspicious ───────────────────────────────────────────────────────────────
function renderSuspicious(files) {
  const tbody = el('sus-body');
  setText('sus-count', files.length + ' ficheros');
  if (!files.length) {
    tbody.innerHTML = '<tr><td colspan="6"><div class="empty"><div class="empty-text">No se detectaron ficheros sospechosos</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = files.map(f => {
    const reasons = (f.reasons || []).map(r => `<span class="tag tag-orange" style="margin-right:3px">${esc(r)}</span>`).join('');
    return `<tr>
      <td>${f.deleted ? '<span class="badge b-del">DEL</span>' : '<span class="badge b-sus">SUS</span>'}</td>
      <td style="font-weight:600;color:var(--orange);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.path)}">${esc(f.name||'—')}</td>
      <td>${reasons}</td>
      <td style="font-family:monospace;color:var(--muted);white-space:nowrap">${esc(fmtTs(f.mtime))}</td>
      <td style="font-family:monospace;color:var(--muted)">${esc(f.inode||'—')}</td>
      <td>
        ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openHex('${esc(f.inode)}')">Hex</button>` : ''}
        ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openInode('${esc(f.inode)}')">Meta</button>` : ''}
      </td>
    </tr>`;
  }).join('');
}

function filterSuspicious() {
  const q = el('sus-search').value.toLowerCase();
  renderSuspicious(q ? _suspicious.filter(f => (f.name||'').toLowerCase().includes(q)
    || (f.reasons||[]).join(' ').toLowerCase().includes(q)) : _suspicious);
}

function sortSus(col) {
  _suspicious.sort((a,b) => String(a[col]||'').localeCompare(String(b[col]||'')));
  renderSuspicious(_suspicious);
}

// ─── Papelera de reciclaje ────────────────────────────────────────────────────
function renderRecycleBin(items) {
  const tbody = el('recycle-body');
  setText('recycle-count', items.length + ' entradas');
  if (!tbody) return;
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="8"><div class="empty"><div class="empty-text">Papelera vacia o no detectada</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = items.map(f => {
    const isI = f.entry_type === 'metadata';
    const isR = f.entry_type === 'contenido';
    const typeLabel = isI ? '<span class="badge b-del" title="Metadatos: contiene nombre original, tamaño y fecha exacta de borrado">$I</span>' :
                      isR ? '<span class="badge b-sus" title="Contenido: fichero recuperable">$R</span>' :
                            '<span class="badge b-file" title="Entrada de papelera">ENT</span>';
    const typeDesc = isI ? 'Metadatos del borrado (nombre, fecha, tamanyo original)' :
                    isR  ? 'Contenido recuperable del fichero borrado' :
                           'Entrada de carpeta papelera';
    return `<tr>
      <td>${typeLabel}</td>
      <td style="color:var(--blue);font-size:11px">${typeDesc}</td>
      <td style="font-weight:600;color:var(--text)">${esc(f.name||'—')}</td>
      <td style="color:var(--muted2);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.path)}">${esc(f.path||'—')}</td>
      <td style="color:var(--muted)">${fmtSize(f.size)}</td>
      <td style="font-family:monospace;color:var(--muted);white-space:nowrap">${esc(fmtTs(f.mtime))}</td>
      <td style="font-family:monospace;color:var(--muted)">${esc(f.inode||'—')}</td>
      <td>
        ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openHex('${esc(f.inode)}')">Hex</button>` : ''}
        ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openInode('${esc(f.inode)}')">Meta</button>` : ''}
      </td>
    </tr>`;
  }).join('');
}

// ─── Elementos de inicio ──────────────────────────────────────────────────────
const _LEGIT_STARTUP = new Set([
  'onedrive.exe','teams.exe','zoom.exe','slack.exe','discord.exe',
  'googledrivesync.exe','dropbox.exe','spotify.exe','steam.exe',
  'adobearm.exe','acrotray.exe','jusched.exe','nvdisplay.container.exe',
  'dellclientmgmtsvctray.exe','securityhealthsystray.exe','vmware-tray.exe',
]);
const _HIGH_RISK_EXT = new Set(['.exe','.dll','.bat','.cmd','.ps1','.vbs','.js','.scr','.hta']);
function _startupRisk(f) {
  const base = (f.name || '').toLowerCase();
  const ext  = base.includes('.') ? '.' + base.split('.').pop() : '';
  if (f.deleted) return {label:'ELIMINADO', cls:'b-del', note:'Eliminar trazas de persistencia'};
  if (!_LEGIT_STARTUP.has(base) && _HIGH_RISK_EXT.has(ext))
    return {label:'REVISAR', cls:'b-sus', note:'Ejecutable desconocido en startup'};
  return {label:'OK', cls:'b-ok', note:'Aplicacion de inicio comun'};
}

function renderStartupItems(items) {
  const tbody = el('startup-body');
  setText('startup-count', items.length + ' elementos');
  if (!tbody) return;
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="8"><div class="empty"><div class="empty-text">Sin elementos de inicio detectados</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = items.map(f => {
    const risk = _startupRisk(f);
    const ext  = (f.name||'').includes('.') ? '.' + (f.name||'').split('.').pop().toLowerCase() : '—';
    return `<tr>
    <td title="${esc(risk.note)}"><span class="badge ${risk.cls}">${risk.label}</span></td>
    <td style="font-weight:600;color:var(--orange)">${esc(f.name||'—')}</td>
    <td style="font-family:monospace;color:var(--muted)">${esc(ext)}</td>
    <td style="color:var(--muted2);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.path)}">${esc(f.path||'—')}</td>
    <td style="color:var(--muted)">${fmtSize(f.size)}</td>
    <td style="font-family:monospace;color:var(--muted);white-space:nowrap">${esc(fmtTs(f.mtime))}</td>
    <td style="font-family:monospace;color:var(--muted)">${esc(f.inode||'—')}</td>
    <td>
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openHex('${esc(f.inode)}')">Hex</button>` : ''}
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openInode('${esc(f.inode)}')">Meta</button>` : ''}
    </td>
  </tr>`;
  }).join('');
}

// ─── Registros de eventos ─────────────────────────────────────────────────────
const _EVTX_RELEVANCE = {
  'Security':          'LOGIN/LOGOUT (4624 OK, 4625 fallo), cuentas (4720/4726), privilegios (4672)',
  'System':            'Arranques, apagados, servicios instalados/detenidos',
  'Application':       'Errores de aplicaciones, crashes, instalaciones',
  'PowerShell':        'Comandos PowerShell ejecutados — CRITICO si hay codificados en base64',
  'PowerShell/Operational': 'Comandos PowerShell ejecutados — CRITICO si hay codificados en base64',
  'Microsoft-Windows-Sysmon/Operational': 'Procesos, red, registro — fuente forense de maxima calidad',
  'Microsoft-Windows-TaskScheduler/Operational': 'Tareas programadas creadas/ejecutadas — vector de persistencia',
  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational': 'Sesiones RDP — accesos remotos',
  'Microsoft-Windows-WinRM/Operational': 'PowerShell remoto — movimiento lateral posible',
  'Microsoft-Windows-Bits-Client/Operational': 'Descargas BITS — usado por malware para descargar payloads',
  'Windows Defender':  'Detecciones de malware, acciones realizadas, exclusiones configuradas',
  'Winlogon':          'Inicio de sesion de Windows, proveedores de credenciales',
  'NTLM':              'Autenticaciones NTLM — puede revelar ataques Pass-the-Hash',
};
function _evtxRelevance(channel) {
  if (!channel) return '—';
  const key = Object.keys(_EVTX_RELEVANCE).find(k =>
    channel.toLowerCase().includes(k.toLowerCase()));
  return key ? _EVTX_RELEVANCE[key] : 'Registros del sistema — revisar para actividad anomala';
}

function renderEventLogs(logs) {
  const tbody = el('events-body');
  setText('events-count', logs.length + ' ficheros');
  if (!tbody) return;
  if (!logs.length) {
    tbody.innerHTML = '<tr><td colspan="8"><div class="empty"><div class="empty-text">Sin registros de eventos detectados</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = logs.map(f => {
    const relevance = _evtxRelevance(f.channel || f.name || '');
    return `<tr>
    <td>${f.deleted ? '<span class="badge b-del" title="ALERTA: fichero eliminado — posible borrado de trazas">DEL</span>' : '<span class="badge b-ok">OK</span>'}</td>
    <td style="font-weight:600;color:var(--text);white-space:nowrap">${esc(f.channel||f.name||'—')}</td>
    <td style="color:var(--muted2);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.path)}">${esc(f.name||'—')}</td>
    <td style="color:var(--blue);font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(relevance)}">${esc(relevance)}</td>
    <td style="color:var(--muted)">${fmtSize(f.size)}</td>
    <td style="font-family:monospace;color:var(--muted);white-space:nowrap">${esc(fmtTs(f.mtime))}</td>
    <td style="font-family:monospace;color:var(--muted)">${esc(f.inode||'—')}</td>
    <td>
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openHex('${esc(f.inode)}')">Hex</button>` : ''}
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openInode('${esc(f.inode)}')">Meta</button>` : ''}
    </td>
  </tr>`;
  }).join('');
}

// ─── Correo electrónico ───────────────────────────────────────────────────────
function renderEmailFiles(emails) {
  const tbody = el('email-body');
  setText('email-count', emails.length + ' ficheros');
  if (!tbody) return;
  if (!emails.length) {
    tbody.innerHTML = '<tr><td colspan="8"><div class="empty"><div class="empty-text">Sin artefactos de correo detectados</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = emails.map(f => `<tr>
    <td>${f.deleted ? '<span class="badge b-del">DEL</span>' : '<span class="badge b-ok">OK</span>'}</td>
    <td style="font-weight:600;color:var(--text)">${esc(f.name||'—')}</td>
    <td><span class="tag tag-blue">${esc(f.format||'—')}</span></td>
    <td style="color:var(--muted2);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.path)}">${esc(f.path||'—')}</td>
    <td style="color:var(--muted)">${fmtSize(f.size)}</td>
    <td style="font-family:monospace;color:var(--muted);white-space:nowrap">${esc(fmtTs(f.mtime))}</td>
    <td style="font-family:monospace;color:var(--muted)">${esc(f.inode||'—')}</td>
    <td>
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openHex('${esc(f.inode)}')">Hex</button>` : ''}
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openInode('${esc(f.inode)}')">Meta</button>` : ''}
    </td>
  </tr>`).join('');
}

// ─── Artefactos de red ────────────────────────────────────────────────────────
const _NET_CONTEXT = {
  'Fichero hosts':   'Comprueba si hay dominios redirigidos a IPs locales (tecnica de malware para redirigir trafico)',
  'Perfil WiFi':     'Contiene SSID y posiblemente clave WiFi en texto plano — revela redes conocidas del equipo',
  'Perfil WiFi (Windows)': 'XML con SSID y tipo de autenticacion; puede incluir la clave en <keyMaterial>',
  'Perfil de red':   'Configuracion de red guardada — revela infraestructura conocida del equipo',
  'Configuracion DNS': 'Servidores DNS configurados — un DNS extrano puede indicar malware o exfiltracion',
  'Hosts SSH conocidos': 'Lista de servidores SSH a los que el usuario se ha conectado antes',
  'Claves SSH autorizadas': 'Claves publicas que pueden acceder a esta maquina por SSH sin contrasena',
  'Configuracion VPN': 'Datos del tunel VPN — puede revelar infraestructura corporativa o C2',
  'Configuracion OpenVPN': 'Fichero de perfil OpenVPN — puede contener credenciales o IP del servidor',
  'Configuracion RDP': 'Perfil de escritorio remoto — revela servidores a los que el usuario se conectaba',
};
function _netContext(desc) {
  const key = Object.keys(_NET_CONTEXT).find(k => desc && desc.includes(k));
  return key ? _NET_CONTEXT[key] : desc || '—';
}

function renderNetworkArtifacts(items) {
  const tbody = el('network-body');
  setText('network-count', items.length + ' artefactos');
  if (!tbody) return;
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty"><div class="empty-text">Sin artefactos de red detectados</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = items.map(f => {
    const context = _netContext(f.description || '');
    return `<tr>
    <td style="font-weight:600;color:var(--text)">${esc(f.name||'—')}</td>
    <td style="color:var(--blue);font-size:11px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(context)}">${esc(context)}</td>
    <td style="color:var(--muted2);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.path)}">${esc(f.path||'—')}</td>
    <td style="color:var(--muted)">${fmtSize(f.size)}</td>
    <td style="font-family:monospace;color:var(--muted);white-space:nowrap">${esc(fmtTs(f.mtime))}</td>
    <td style="font-family:monospace;color:var(--muted)">${esc(f.inode||'—')}</td>
    <td>
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openHex('${esc(f.inode)}')">Hex</button>` : ''}
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openInode('${esc(f.inode)}')">Meta</button>` : ''}
    </td>
  </tr>`;
  }).join('');
}

// ─── Trazas USB ───────────────────────────────────────────────────────────────
function _usbContext(name) {
  const n = (name || '').toLowerCase();
  if (n.includes('setupapi')) return 'Log de instalacion de drivers — contiene timestamps y VID/PID de cada dispositivo USB conectado';
  if (n.includes('usbstor'))  return 'Registro de dispositivos de almacenamiento USB — numero de serie, fabricante y modelo';
  if (n.includes('usbstore')) return 'Historial de dispositivos USB del sistema';
  return 'Traza de conexion de dispositivo USB — prueba que un dispositivo estuvo conectado';
}

function renderUsbTraces(items) {
  const tbody = el('usb-body');
  setText('usb-count', items.length + ' trazas');
  if (!tbody) return;
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty"><div class="empty-text">Sin trazas de dispositivos USB detectadas</div></div></td></tr>';
    return;
  }
  tbody.innerHTML = items.map(f => {
    const ctx = _usbContext(f.name);
    return `<tr>
    <td style="font-weight:600;color:var(--text)">${esc(f.name||'—')}</td>
    <td style="color:var(--blue);font-size:11px;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(ctx)}">${esc(ctx)}</td>
    <td style="color:var(--muted2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.path)}">${esc(f.path||'—')}</td>
    <td style="color:var(--muted)">${fmtSize(f.size)}</td>
    <td style="font-family:monospace;color:var(--muted);white-space:nowrap">${esc(fmtTs(f.mtime))}</td>
    <td style="font-family:monospace;color:var(--muted)">${esc(f.inode||'—')}</td>
    <td>
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openHex('${esc(f.inode)}')">Hex</button>` : ''}
      ${f.inode && f.inode !== '—' ? `<button class="btn" style="padding:3px 8px;font-size:11px" onclick="openInode('${esc(f.inode)}')">Meta</button>` : ''}
    </td>
  </tr>`;
  }).join('');
}

// ─── Strings ──────────────────────────────────────────────────────────────────
function renderStrings(strings) {
  if (strings._skipped) {
    const notice = `<div class="empty" style="grid-column:1/-1">
      <div class="empty-text" style="color:var(--orange)">${esc(strings._skipped)}</div>
    </div>`;
    for (const k of ['urls','emails','ips','paths','other']) {
      el('stc-' + k).textContent = '—';
      el('sg-' + k).innerHTML = notice;
    }
    return;
  }
  for (const k of ['urls','emails','ips','paths','other']) {
    const items = strings[k] || [];
    el('stc-' + k).textContent = items.length;
    const grid = el('sg-' + k);
    if (!items.length) {
      grid.innerHTML = `<div class="empty"><div class="empty-text">Sin ${k}</div></div>`;
      continue;
    }
    grid.innerHTML = items.map(s =>
      `<div class="str-item" onclick="copyStr(this,'${esc(s).replace(/'/g,"\\'")}')"><span>${esc(s)}</span></div>`
    ).join('');
  }
}

function filterStrings() {
  if (!D || D.strings?._skipped) return;
  const q = el('str-search').value.toLowerCase();
  for (const k of ['urls','emails','ips','paths','other']) {
    const items = (D.strings?.[k] || []).filter(s => !q || s.toLowerCase().includes(q));
    const grid = el('sg-' + k);
    grid.innerHTML = items.map(s =>
      `<div class="str-item" onclick="copyStr(this,'${esc(s).replace(/'/g,"\\'")}')"><span>${esc(s)}</span></div>`
    ).join('') || `<div class="empty"><div class="empty-text">Sin resultados</div></div>`;
  }
}

function switchStrTab(tab) {
  _strTabActive = tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  el('stab-' + tab)?.classList.add('active');
  el('spanel-' + tab)?.classList.add('active');
}

function copyStr(el, s) {
  navigator.clipboard?.writeText(s).then(() => {
    el.classList.add('copied');
    setTimeout(() => el.classList.remove('copied'), 1200);
  });
}

// ─── Timeline ─────────────────────────────────────────────────────────────────
let _tlFull = [];
function buildTimeline(files) {
  _tlFull = files
    .filter(f => f.mtime && f.mtime !== '—' && f.mtime !== '0')
    .sort((a, b) => String(b.mtime).localeCompare(String(a.mtime)))
    .slice(0, 2000);
  setText('tl-count', _tlFull.length + ' eventos');
  renderTimeline(_tlFull);
}

function renderTimeline(files) {
  const body = el('tl-body');
  if (!files.length) {
    body.innerHTML = '<div class="empty"><div class="empty-text">Sin datos de timeline</div></div>';
    return;
  }
  body.innerHTML = files.slice(0, 500).map(f => {
    const isDel = f.deleted, isDir = f.type === 'dir';
    const dot   = isDel ? 'var(--red)' : isDir ? 'var(--green)' : 'var(--blue)';
    const type  = isDel ? 'DELETED' : isDir ? 'DIR' : 'FILE';
    return `<div class="tl-item">
      <div class="tl-dot" style="background:${dot}"></div>
      <div class="tl-time">${esc(fmtTs(f.mtime))}</div>
      <div class="tl-name" title="${esc(f.name||f.raw||'')}">${esc(f.name||f.raw||'—')}</div>
      <div class="tl-type" style="color:${dot}">${type}</div>
    </div>`;
  }).join('');
}

function filterTimeline() {
  const q  = el('tl-search').value.toLowerCase();
  const ft = el('tl-filter').value;
  const filtered = _tlFull.filter(f => {
    const matchQ = !q || (f.name || '').toLowerCase().includes(q);
    const type   = f.deleted ? 'deleted' : (f.type || '');
    const matchF = !ft || type === ft;
    return matchQ && matchF;
  });
  setText('tl-count', filtered.length + ' eventos');
  renderTimeline(filtered);
}

// ─── Hex viewer ───────────────────────────────────────────────────────────────
function openHex(inode) {
  el('hex-inode').value = inode;
  nav('hex');
  loadHex();
}

async function loadHex() {
  if (!_fileId) { toast('No hay caso abierto', 'err'); return; }
  const inode    = el('hex-inode').value.trim();
  const maxBytes = Math.min(parseInt(el('hex-bytes').value) || 4096, 65536);
  if (!inode) { toast('Introduce un número de inode', 'err'); return; }

  el('hex-display').innerHTML = '<div class="hex-empty">Cargando...</div>';
  el('hex-info').textContent = '';

  try {
    const res  = await fetch(`/api/file/${_fileId}/${inode}?max_bytes=${maxBytes}`, {
      headers: {'X-CSRF-TOKEN': CSRF},
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.error || 'Error ' + res.status);
    }
    const data    = await res.json();
    const b64     = data.content_b64 || '';
    const raw     = atob(b64);
    const bytes   = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    el('hex-info').textContent = `${bytes.length} bytes · inode ${inode}`;
    el('hex-display').innerHTML = renderHex(bytes);
  } catch (err) {
    el('hex-display').innerHTML = `<div class="hex-empty">${esc(err.message)}</div>`;
    toast(err.message, 'err');
  }
}

function renderHex(bytes) {
  const COLS = 16;
  let out = '';
  for (let i = 0; i < bytes.length; i += COLS) {
    const row   = bytes.slice(i, i + COLS);
    const off   = i.toString(16).padStart(8, '0');
    const hexPart = Array.from(row).map((b, j) => {
      const h = b.toString(16).padStart(2, '0');
      const cls = b === 0 ? 'hex-zero' : 'hex-byte';
      return `<span class="${cls}">${h}</span>`;
    });
    // Pad to 16 cols
    while (hexPart.length < COLS) hexPart.push('<span class="hex-zero">  </span>');
    const mid   = hexPart.slice(0, 8).join(' ') + '  ' + hexPart.slice(8).join(' ');
    const ascii = Array.from(row).map(b => {
      const c = b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
      return esc(c);
    }).join('');
    out += `<span class="hex-offset">${off}</span>  ${mid}  <span class="hex-ascii">|${ascii}|</span>\n`;
  }
  return out || '<div class="hex-empty">Sin datos</div>';
}

// ─── Inode inspector ─────────────────────────────────────────────────────────
function openInode(inode) {
  el('inode-input').value = inode;
  nav('inode');
  inspectInode();
}

async function inspectInode() {
  if (!_fileId) { toast('No hay caso abierto', 'err'); return; }
  const inode = el('inode-input').value.trim();
  if (!inode) return;
  el('inode-out').textContent = 'Consultando...';
  try {
    const res  = await fetch(`/api/metadata/${_fileId}/${inode}?offset=${_imgOffset}`, {
      headers: {'X-CSRF-TOKEN': CSRF},
    });
    const data = await res.json();
    el('inode-out').textContent = data.istat || JSON.stringify(data, null, 2);
  } catch (err) {
    el('inode-out').textContent = 'Error: ' + err.message;
  }
}
el('inode-input').addEventListener('keydown', e => { if (e.key === 'Enter') inspectInode(); });
el('hex-inode').addEventListener('keydown',   e => { if (e.key === 'Enter') loadHex(); });

// ─── Export ───────────────────────────────────────────────────────────────────
function showExport() {
  const m = el('export-menu');
  m.style.display = m.style.display === 'none' ? 'block' : 'none';
}
document.addEventListener('click', e => {
  if (!e.target.closest('#export-wrap') && !e.target.closest('#export-btn'))
    el('export-menu').style.display = 'none';
});

function doExport(type) {
  el('export-menu').style.display = 'none';
  if (!D) return;
  let blob, name;
  if (type === 'json') {
    blob = new Blob([JSON.stringify(D, null, 2)], {type: 'application/json'});
    name = `${D.filename}_analysis.json`;
  } else if (type === 'csv') {
    const rows = [['Tipo','Nombre','Inode','Tamaño','Modificado','Eliminado']];
    (_allFiles || []).forEach(f => rows.push([
      f.type||'file', f.name||f.raw||'', f.inode||'', f.size||'',
      fmtTs(f.mtime), f.deleted ? 'Sí' : 'No',
    ]));
    blob = new Blob([rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n')],
                   {type: 'text/csv;charset=utf-8'});
    name = `${D.filename}_files.csv`;
  } else {
    generateReport();
    nav('report');
    return;
  }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  toast('Descarga iniciada', 'ok');
}

// ─── Report ───────────────────────────────────────────────────────────────────
function generateReport() {
  if (!D) return;
  const S   = '═'.repeat(72);
  const s   = '─'.repeat(72);
  const s2  = '  ' + '─'.repeat(68);
  const h   = D.hashes || {};
  const os  = D.os_info || {};
  const bi  = D.backend_info || {};
  const bh  = D.browser_history || {};
  const ra  = D.recent_activity || {};
  const str = D.strings || {};
  const now = new Date();

  function pad(label, val, width = 22) {
    return '  ' + (label + ':').padEnd(width) + (val ?? '—') + '\n';
  }
  function section(title) {
    return '\n' + s + '\n  ' + title.toUpperCase() + '\n' + s + '\n';
  }
  function subsection(title) {
    return '\n' + s2 + '\n  ' + title + '\n' + s2 + '\n';
  }

  let r = '';
  r += S + '\n';
  r += '  INFORME DE ANÁLISIS FORENSE DIGITAL\n';
  r += '  CaseAnalyzer v4.0 — Herramienta de Análisis de Evidencias Digitales\n';
  r += S + '\n\n';

  // 1. IDENTIFICACIÓN
  r += section('1. IDENTIFICACIÓN DE LA EVIDENCIA');
  r += pad('Fichero analizado', D.filename);
  r += pad('Tamaño de imagen',  fmtSize(D.file_size));
  r += pad('Tipo de imagen',    D.image_type?.type);
  r += pad('Entropía',          (D.entropy ?? '—') + ' bits/byte');
  r += pad('Fecha del análisis',now.toLocaleString('es-ES'));
  r += pad('Backend empleado',  bi.active);
  r += pad('Capacidades',
    'pytsk3:' + (bi.pytsk3?'✓':'✗') +
    ' TSK:' + (bi.tsk_bin?'✓':'✗') +
    ' WSL:' + (bi.wsl?'✓':'✗') +
    ' 7zip:' + (bi['7zip']?'✓':'✗'));

  // 2. HASHES
  r += section('2. VERIFICACIÓN DE INTEGRIDAD (HASHES)');
  r += pad('MD5',    h.md5);
  r += pad('SHA-1',  h.sha1);
  r += pad('SHA-256',h.sha256);
  r += pad('Alcance',h.note);

  // 3. SISTEMA OPERATIVO Y FILESYSTEM
  r += section('3. SISTEMA OPERATIVO Y FILESYSTEM');
  const osConf = os.confidence === 'alta' ? 'ALTA' : os.confidence === 'media' ? 'MEDIA' : 'BAJA';
  r += pad('SO detectado',  (os.os || '—') + (os.version ? ' ' + os.version : ''));
  r += pad('Confianza',     osConf);
  if (D.image_info?.partitions && D.image_info.partitions !== '(sin tabla)') {
    r += subsection('Tabla de particiones');
    r += D.image_info.partitions.split('\n').map(l => '  ' + l).join('\n') + '\n';
  }

  // 4. RESUMEN ESTADÍSTICO
  r += section('4. RESUMEN ESTADÍSTICO');
  r += pad('Ficheros totales',    D.total_files || 0);
  r += pad('Ficheros eliminados', D.total_deleted || 0);
  r += pad('Usuarios detectados', (D.users || []).length);
  r += pad('Fich. sospechosos',   (D.suspicious_files || []).length);
  r += pad('Visitas web',         (bh.visits || []).length);
  r += pad('Descargas web',       (bh.downloads || []).length);
  r += pad('Búsquedas web',       (bh.searches || []).length);
  r += pad('Archivos LNK',        (ra.lnk || []).length);
  r += pad('Entradas Prefetch',   (ra.prefetch || []).length);
  r += pad('Hives de registro',   (ra.registry_hives || []).length);
  r += pad('URLs encontradas',    (str.urls || []).length);
  r += pad('Emails encontrados',  (str.emails || []).length);
  r += pad('IPs encontradas',     (str.ips || []).length);
  r += pad('Reg. de eventos',     (D.event_logs || []).length);
  r += pad('Ficheros de correo',  (D.email_files || []).length);
  r += pad('Inicio automático',   (D.startup_items || []).length);
  r += pad('Papelera (entradas)', (D.recycle_bin || []).length);
  r += pad('Trazas USB',          (D.usb_traces || []).length);
  r += pad('Artefactos de red',   (D.network_artifacts || []).length);

  // 5. TIPOS DE FICHERO
  if (D.file_types && Object.keys(D.file_types).length) {
    r += section('5. DISTRIBUCIÓN POR TIPO DE FICHERO');
    const sorted = Object.entries(D.file_types).sort((a,b) => b[1].count - a[1].count);
    sorted.forEach(([cat, info]) => {
      const topExts = Object.entries(info.extensions || {}).sort((a,b)=>b[1]-a[1]).slice(0,5)
        .map(([e,c]) => e + '(' + c + ')').join(', ');
      r += `  ${(cat + ':').padEnd(18)} ${String(info.count).padStart(5)} ficheros  ${topExts}\n`;
    });
  }

  // 6. USUARIOS
  if ((D.users || []).length) {
    r += section('6. CUENTAS DE USUARIO DETECTADAS');
    D.users.forEach(u => {
      r += `  Cuenta  : ${u.name}\n`;
      r += `  Sistema : ${u.os}\n`;
      r += `  Ficheros: ${u.files}\n`;
      r += `  Último acceso: ${fmtTs(u.last_seen) || '—'}\n\n`;
    });
  }

  // 7. FICHEROS ELIMINADOS
  if ((D.deleted || []).length) {
    r += section('7. FICHEROS ELIMINADOS (RECUPERABLES)');
    r += `  Total de ficheros eliminados: ${D.deleted.length}\n\n`;
    D.deleted.slice(0, 50).forEach(f => {
      r += `  ${f.name || f.raw || '—'}\n`;
    });
    if (D.deleted.length > 50) r += `  ... y ${D.deleted.length - 50} más\n`;
  }

  // 8. FICHEROS SOSPECHOSOS
  if ((D.suspicious_files || []).length) {
    r += section('8. FICHEROS SOSPECHOSOS / INDICADORES DE COMPROMISO');
    D.suspicious_files.slice(0, 50).forEach(f => {
      r += `  Fichero : ${f.name}\n`;
      r += `  Ruta    : ${f.path}\n`;
      r += `  Motivo  : ${(f.reasons || []).join('; ')}\n`;
      r += `  mtime   : ${fmtTs(f.mtime) || '—'}\n`;
      r += `  Inode   : ${f.inode || '—'}\n\n`;
    });
  }

  // 9. ACTIVIDAD RECIENTE — LNK
  if ((ra.lnk || []).length) {
    r += section('9. ARCHIVOS LNK (ACCESOS RECIENTES)');
    ra.lnk.slice(0, 30).forEach(f => {
      r += `  ${f.name.padEnd(40)} ${fmtTs(f.mtime) || '—'}\n  Ruta: ${f.path}\n\n`;
    });
  }

  // 10. PREFETCH
  if ((ra.prefetch || []).length) {
    r += section('10. ENTRADAS PREFETCH (PROGRAMAS EJECUTADOS)');
    ra.prefetch.slice(0, 30).forEach(f => {
      r += `  ${(f.exe || f.name || '—').padEnd(40)} ${fmtTs(f.mtime) || '—'}\n`;
    });
  }

  // 11. REGISTRO DE WINDOWS
  if ((ra.registry_hives || []).length) {
    r += section('11. HIVES DEL REGISTRO DE WINDOWS');
    ra.registry_hives.forEach(h => {
      r += `  ${h.name.padEnd(20)} Ruta: ${h.path}  Inode: ${h.inode || '—'}\n`;
    });
  }

  // 12. HISTORIAL WEB
  if ((bh.visits || []).length) {
    r += section('12. HISTORIAL DE NAVEGACIÓN WEB');
    bh.visits.slice(0, 30).forEach(v =>
      r += `  [${(v.browser || '?').padEnd(8)}] ${(fmtTs(v.time) || '—').padEnd(20)} ${v.url}\n`);
  }

  if ((bh.searches || []).length) {
    r += subsection('Búsquedas realizadas');
    bh.searches.slice(0, 30).forEach(s => r += `  ${s}\n`);
  }

  if ((bh.downloads || []).length) {
    r += subsection('Descargas');
    bh.downloads.slice(0, 20).forEach(d =>
      r += `  ${fmtTs(d.time) || '—'}  ${fmtSize(d.size)}  ${d.path}\n`);
  }

  // 13. STRINGS E IoC
  r += section('13. INDICADORES DE COMPROMISO (IoC) — STRINGS');
  if ((str.urls || []).length) {
    r += subsection('URLs (' + str.urls.length + ')');
    str.urls.slice(0, 30).forEach(u => r += `  ${u}\n`);
  }
  if ((str.emails || []).length) {
    r += subsection('Direcciones de correo (' + str.emails.length + ')');
    str.emails.slice(0, 20).forEach(e => r += `  ${e}\n`);
  }
  if ((str.ips || []).length) {
    r += subsection('Direcciones IP (' + str.ips.length + ')');
    str.ips.slice(0, 20).forEach(ip => r += `  ${ip}\n`);
  }
  if ((str.paths || []).length) {
    r += subsection('Rutas de sistema (' + str.paths.length + ')');
    str.paths.slice(0, 20).forEach(p => r += `  ${p}\n`);
  }

  // 14. REGISTROS DE EVENTOS
  if ((D.event_logs || []).length) {
    r += section('14. REGISTROS DE EVENTOS DE WINDOWS (.EVTX)');
    r += '  Los ficheros EVTX contienen logins, accesos a recursos, errores y actividad del sistema.\n';
    r += '  Canales clave: Security (4624/4625 logins), System (arranques/errores), PowerShell, Sysmon.\n\n';
    D.event_logs.forEach(f => {
      r += `  [${(f.format || 'EVTX').padEnd(4)}] ${(f.channel || f.name || '—').padEnd(52)} ${fmtTs(f.mtime) || '—'}\n`;
      r += `         Fichero: ${f.name}  Tamaño: ${fmtSize(f.size)}\n`;
      r += `         Ruta:    ${f.path}\n`;
      if (f.deleted) r += `         ALERTA: FICHERO ELIMINADO — posible borrado deliberado de trazas\n`;
      r += '\n';
    });
  }

  // 15. ARTEFACTOS DE CORREO
  if ((D.email_files || []).length) {
    r += section('15. ARTEFACTOS DE CORREO ELECTRÓNICO');
    r += '  PST/OST: buzones Outlook completos. EML/MSG: mensajes individuales.\n';
    r += '  MBOX: Thunderbird/Evolution. Requieren herramientas específicas para lectura.\n\n';
    D.email_files.forEach(f => {
      r += `  ${(f.name || '—').padEnd(42)} [${(f.format || '—').padEnd(28)}]  ${fmtTs(f.mtime) || '—'}\n`;
      r += `         Ruta:    ${f.path}  Tamaño: ${fmtSize(f.size)}\n`;
      if (f.deleted) r += `         ALERTA: FICHERO ELIMINADO\n`;
      r += '\n';
    });
  }

  // 16. ELEMENTOS DE INICIO AUTOMÁTICO
  if ((D.startup_items || []).length) {
    r += section('16. ELEMENTOS DE INICIO AUTOMÁTICO (PERSISTENCIA)');
    r += '  Ficheros en carpetas Startup o menú de inicio. Mecanismo habitual de persistencia de malware.\n';
    r += '  Verificar que todos los ejecutables son legítimos.\n\n';
    D.startup_items.forEach(f => {
      r += `  ${(f.name || '—').padEnd(42)} ${fmtTs(f.mtime) || '—'}\n`;
      r += `         Ruta: ${f.path}  Tamaño: ${fmtSize(f.size)}\n`;
      if (f.deleted) r += `         ALERTA: ELIMINADO — posible intento de borrar rastros de persistencia\n`;
      r += '\n';
    });
  }

  // 17. PAPELERA DE RECICLAJE
  if ((D.recycle_bin || []).length) {
    r += section('17. PAPELERA DE RECICLAJE ($RECYCLE.BIN / RECYCLER)');
    r += '  $I: metadatos (nombre original, tamaño, fecha de eliminación).\n';
    r += '  $R: contenido del fichero original — recuperable con herramientas forenses.\n\n';
    D.recycle_bin.forEach(f => {
      const tl = f.entry_type === 'metadata' ? '$I — metadatos  ' :
                 f.entry_type === 'contenido' ? '$R — recuperable' : 'entrada         ';
      r += `  [${tl}] ${(f.name || '—').padEnd(32)} ${fmtTs(f.mtime) || '—'}  ${fmtSize(f.size)}\n`;
      r += `         Ruta: ${f.path}\n\n`;
    });
  }

  // 18. TRAZAS USB
  if ((D.usb_traces || []).length) {
    r += section('18. TRAZAS DE DISPOSITIVOS USB');
    r += '  setupapi.dev.log: historial de instalación de dispositivos con timestamps y GUIDs.\n';
    r += '  Para GUIDs completos analizar HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR.\n\n';
    D.usb_traces.forEach(f => {
      r += `  ${(f.name || '—').padEnd(42)} ${fmtTs(f.mtime) || '—'}\n`;
      r += `         Ruta: ${f.path}\n\n`;
    });
  }

  // 19. ARTEFACTOS DE RED
  if ((D.network_artifacts || []).length) {
    r += section('19. ARTEFACTOS DE RED Y CONECTIVIDAD');
    r += '  Perfiles WiFi, configuración DNS, hosts, VPN, SSH — revelan redes e infraestructura conocidas.\n\n';
    D.network_artifacts.forEach(f => {
      r += `  ${(f.name || '—').padEnd(32)} ${(f.description || '—').padEnd(40)} ${fmtTs(f.mtime) || '—'}\n`;
      r += `         Ruta: ${f.path}\n\n`;
    });
  }

  // FIN
  r += '\n' + S + '\n';
  r += '  FIN DEL INFORME\n';
  r += '  Generado por CaseAnalyzer v4.0 el ' + now.toLocaleString('es-ES') + '\n';
  r += S + '\n';
  el('report-output').textContent = r;
}

function copyReport() {
  const text = el('report-output').textContent;
  navigator.clipboard?.writeText(text).then(() => toast('Informe copiado', 'ok'));
}

function downloadReport() {
  if (!D) return;
  const text = el('report-output').textContent;
  const blob = new Blob([text], {type: 'text/plain;charset=utf-8'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `informe_${D.filename}_${new Date().toISOString().slice(0,10)}.txt`;
  a.click();
  toast('Informe descargado', 'ok');
}