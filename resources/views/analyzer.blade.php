<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf-token" content="{{ csrf_token() }}">
<title>CaseAnalyzer</title>
<link rel="stylesheet" href="{{ asset('css/analyzer.css') }}">
</head>
<body>

{{-- ── TOPBAR ──────────────────────────────────────────────────── --}}
<header id="topbar">
  <div class="tb-logo">CaseAnalyzer <span>v4.0</span></div>
  <div class="tb-case" id="tb-case">Sin caso abierto</div>
  <div class="tb-actions">
    <div style="display:flex;align-items:center;gap:6px;margin-right:4px">
      <div id="health-dot"></div>
      <span id="health-txt">comprobando...</span>
    </div>
    <button class="btn" id="export-btn" disabled onclick="showExport()">Exportar</button>
    <div style="position:relative" id="export-wrap">
      <div id="export-menu" style="display:none;position:absolute;right:0;top:calc(100% + 4px);background:var(--s1);border:1px solid var(--border);border-radius:var(--r);z-index:100;min-width:160px">
        <div class="btn" style="display:block;border:none;border-radius:0;padding:8px 14px" onclick="doExport('json')">JSON completo</div>
        <div class="btn" style="display:block;border:none;border-radius:0;padding:8px 14px" onclick="doExport('csv')">CSV archivos</div>
        <div class="btn" style="display:block;border:none;border-radius:0;padding:8px 14px" onclick="doExport('report')">Informe forense</div>
      </div>
    </div>
    <button class="btn btn-danger" id="new-btn" style="display:none" onclick="newCase()">Nuevo caso</button>
  </div>
</header>

{{-- ── WORKSPACE ────────────────────────────────────────────────── --}}
<div id="workspace">

{{-- ── SIDEBAR ──────────────────────────────────────────────────── --}}
<aside id="sidebar">
  <div id="sidebar-case">
    <div class="sc-label">Caso activo</div>
    <div class="sc-name" id="sc-name">—</div>
    <div class="sc-meta" id="sc-meta">—</div>
  </div>
  <div id="sidebar-tree">

    <div class="tree-group open" id="tg-source">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-source')">CASO <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item active" onclick="nav('overview')" id="ti-overview">
          <span class="ti-label">Resumen ejecutivo</span>
        </div>
      </div>
    </div>

    <div class="tree-group open" id="tg-disk">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-disk')">IMAGEN DE DISCO <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('partitions')" id="ti-partitions">
          <span class="ti-label">Volumen y particiones</span>
        </div>
      </div>
    </div>

    <div class="tree-group open" id="tg-fs">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-fs')">SISTEMA DE FICHEROS <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('files')" id="ti-files">
          <span class="ti-label">Árbol de ficheros</span>
          <span class="ti-badge" id="bd-files">0</span>
        </div>
        <div class="tree-item" onclick="nav('deleted')" id="ti-deleted">
          <span class="ti-label">Ficheros eliminados</span>
          <span class="ti-badge" id="bd-deleted">0</span>
        </div>
        <div class="tree-item" onclick="nav('filetypes')" id="ti-filetypes">
          <span class="ti-label">Clasificación por tipo</span>
        </div>
        <div class="tree-item" onclick="nav('recycle')" id="ti-recycle">
          <span class="ti-label">Papelera de reciclaje</span>
          <span class="ti-badge" id="bd-recycle">0</span>
        </div>
      </div>
    </div>

    <div class="tree-group open" id="tg-exec">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-exec')">EJECUCIÓN <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('prefetch')" id="ti-prefetch">
          <span class="ti-label">Prefetch — programas ejecutados</span>
          <span class="ti-badge" id="bd-prefetch">0</span>
        </div>
        <div class="tree-item" onclick="nav('startup')" id="ti-startup">
          <span class="ti-label">Elementos de inicio</span>
          <span class="ti-badge" id="bd-startup">0</span>
        </div>
        <div class="tree-item" onclick="nav('events')" id="ti-events">
          <span class="ti-label">Registros de eventos</span>
          <span class="ti-badge" id="bd-events">0</span>
        </div>
      </div>
    </div>

    <div class="tree-group open" id="tg-activity">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-activity')">ACTIVIDAD DE USUARIO <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('lnk')" id="ti-lnk">
          <span class="ti-label">Accesos directos (LNK)</span>
          <span class="ti-badge" id="bd-lnk">0</span>
        </div>
      </div>
    </div>

    <div class="tree-group open" id="tg-registry">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-registry')">REGISTRO DE WINDOWS <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('registry')" id="ti-registry">
          <span class="ti-label">Hives del registro</span>
          <span class="ti-badge" id="bd-registry">0</span>
        </div>
      </div>
    </div>

    <div class="tree-group open" id="tg-web">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-web')">NAVEGACIÓN WEB <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('history')" id="ti-history">
          <span class="ti-label">Historial de navegación</span>
          <span class="ti-badge" id="bd-history">0</span>
        </div>
        <div class="tree-item" onclick="nav('downloads')" id="ti-downloads">
          <span class="ti-label">Descargas</span>
          <span class="ti-badge" id="bd-downloads">0</span>
        </div>
        <div class="tree-item" onclick="nav('searches')" id="ti-searches">
          <span class="ti-label">Búsquedas web</span>
          <span class="ti-badge" id="bd-searches">0</span>
        </div>
      </div>
    </div>

    <div class="tree-group open" id="tg-comms">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-comms')">COMUNICACIONES <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('email')" id="ti-email">
          <span class="ti-label">Correo electrónico</span>
          <span class="ti-badge" id="bd-email">0</span>
        </div>
      </div>
    </div>

    <div class="tree-group open" id="tg-infra">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-infra')">RED Y DISPOSITIVOS <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('network')" id="ti-network">
          <span class="ti-label">Artefactos de red</span>
          <span class="ti-badge" id="bd-network">0</span>
        </div>
        <div class="tree-item" onclick="nav('usb')" id="ti-usb">
          <span class="ti-label">Dispositivos USB</span>
          <span class="ti-badge" id="bd-usb">0</span>
        </div>
      </div>
    </div>

    <div class="tree-group open" id="tg-accounts">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-accounts')">CUENTAS <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('users')" id="ti-users">
          <span class="ti-label">Cuentas detectadas</span>
          <span class="ti-badge" id="bd-users">0</span>
        </div>
      </div>
    </div>

    <div class="tree-group open" id="tg-strings">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-strings')">INDICADORES DE COMPROMISO <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('strings','urls')" id="ti-urls">
          <span class="ti-label">URLs</span>
          <span class="ti-badge" id="bd-urls">0</span>
        </div>
        <div class="tree-item" onclick="nav('strings','emails')" id="ti-emails">
          <span class="ti-label">Direcciones email</span>
          <span class="ti-badge" id="bd-emails">0</span>
        </div>
        <div class="tree-item" onclick="nav('strings','ips')" id="ti-ips">
          <span class="ti-label">Direcciones IP</span>
          <span class="ti-badge" id="bd-ips">0</span>
        </div>
        <div class="tree-item" onclick="nav('strings','paths')" id="ti-paths">
          <span class="ti-label">Rutas del sistema</span>
          <span class="ti-badge" id="bd-paths">0</span>
        </div>
        <div class="tree-item" onclick="nav('strings','other')" id="ti-other">
          <span class="ti-label">Strings relevantes</span>
        </div>
      </div>
    </div>

    <div class="tree-group open" id="tg-threats">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-threats')">ANÁLISIS DE AMENAZAS <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('suspicious')" id="ti-suspicious">
          <span class="ti-label">Ficheros sospechosos</span>
          <span class="ti-badge" id="bd-suspicious">0</span>
        </div>
      </div>
    </div>

    <div class="tree-group" id="tg-tools">
      <div class="tree-group-hdr" onclick="toggleGroup('tg-tools')">HERRAMIENTAS FORENSES <span class="tree-chevron">▶</span></div>
      <div class="tree-children">
        <div class="tree-item" onclick="nav('timeline')" id="ti-timeline">
          <span class="ti-label">Timeline de actividad</span>
        </div>
        <div class="tree-item" onclick="nav('hex')" id="ti-hex">
          <span class="ti-label">Visor hexadecimal</span>
        </div>
        <div class="tree-item" onclick="nav('inode')" id="ti-inode">
          <span class="ti-label">Inspector de inode</span>
        </div>
        <div class="tree-item" onclick="nav('report')" id="ti-report">
          <span class="ti-label">Informe forense</span>
        </div>
      </div>
    </div>

  </div>
  <div id="sidebar-footer" id="sf-backend">
    <div class="bc-row"><div class="bc-dot" id="bc-pytsk3"></div> pytsk3</div>
    <div class="bc-row"><div class="bc-dot" id="bc-tsk"></div> TSK binaries</div>
    <div class="bc-row"><div class="bc-dot" id="bc-wsl"></div> WSL+SleuthKit</div>
    <div class="bc-row"><div class="bc-dot" id="bc-7zip"></div> 7-Zip</div>
  </div>
</aside>

{{-- ── MAIN CONTENT ─────────────────────────────────────────────── --}}
<main id="main">

  {{-- UPLOAD --}}
  <section class="section active" id="s-upload">
    <div class="upload-center">
      <div id="drop-zone" tabindex="0" role="button" aria-label="Subir imagen forense"
           onclick="document.getElementById('file-input').click()"
           ondragover="event.preventDefault();this.classList.add('dragover')"
           ondragleave="this.classList.remove('dragover')"
           ondrop="event.preventDefault();this.classList.remove('dragover');if(event.dataTransfer.files.length)upload(event.dataTransfer.files)">
        <div class="dz-icon">[ DD ]</div>
        <div class="dz-title">Arrastra una imagen forense</div>
        <div class="dz-sub">o haz clic para seleccionar · Para archivos multiparte selecciona todos los volúmenes a la vez</div>
        <div class="dz-exts">
          <span class="dz-ext">.dd</span><span class="dz-ext">.img</span>
          <span class="dz-ext">.raw</span><span class="dz-ext">.iso</span>
          <span class="dz-ext">.E01</span><span class="dz-ext">.7z</span>
          <span class="dz-ext">.001</span><span class="dz-ext">.002</span><span class="dz-ext">.003</span><span class="dz-ext">.bin</span>
        </div>
      </div>
      <input type="file" id="file-input" multiple accept=".dd,.img,.raw,.iso,.e01,.E01,.001,.002,.003,.004,.005,.006,.007,.008,.009,.bin,.7z">
      <div id="progress-box">
        <div class="pb-header">
          <span class="pb-title" id="pb-title">Preparando...</span>
          <span class="pb-pct" id="pb-pct">0%</span>
        </div>
        <div class="pb-track"><div id="pb-bar"></div></div>
        <div class="pb-steps" id="pb-steps"></div>
      </div>
    </div>
  </section>

  {{-- Banner imágenes adicionales --}}
  <div id="additional-images-banner" style="display:none"></div>

  {{-- OVERVIEW --}}
  <section class="section" id="s-overview">
    <div class="s-header">
      <div>
        <div class="s-title" id="ov-filename">Resumen del caso</div>
        <div class="s-subtitle" id="ov-subtitle"></div>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <span class="tag" id="ov-os-tag">—</span>
      </div>
    </div>
    <div class="s-body">
      <div id="ov-warn-banner" style="display:none;margin-bottom:16px;padding:12px 16px;background:#2d1b1b;border:1px solid var(--red);border-radius:var(--r);color:#f97171;font-size:13px"></div>
      <div class="stat-grid">
        <div class="stat-card c-blue">
          <div class="stat-val" id="ov-total">—</div>
          <div class="stat-label">Ficheros</div>
        </div>
        <div class="stat-card c-red">
          <div class="stat-val" id="ov-del">—</div>
          <div class="stat-label">Eliminados</div>
        </div>
        <div class="stat-card c-orange">
          <div class="stat-val" id="ov-suspicious">—</div>
          <div class="stat-label">Sospechosos</div>
        </div>
        <div class="stat-card c-green">
          <div class="stat-val" id="ov-users-c">—</div>
          <div class="stat-label">Usuarios detectados</div>
        </div>
        <div class="stat-card c-purple">
          <div class="stat-val" id="ov-history-c">—</div>
          <div class="stat-label">Visitas web</div>
        </div>
        <div class="stat-card c-cyan">
          <div class="stat-val" id="ov-lnk-c">—</div>
          <div class="stat-label">LNK / Prefetch</div>
        </div>
        <div class="stat-card c-blue">
          <div class="stat-val" id="ov-urls">—</div>
          <div class="stat-label">URLs en strings</div>
        </div>
        <div class="stat-card c-blue">
          <div class="stat-val" id="ov-emails">—</div>
          <div class="stat-label">Emails en strings</div>
        </div>
        <div class="stat-card c-orange">
          <div class="stat-val" id="ov-events">—</div>
          <div class="stat-label">Reg. de eventos</div>
        </div>
        <div class="stat-card c-orange">
          <div class="stat-val" id="ov-startup">—</div>
          <div class="stat-label">Inicio automático</div>
        </div>
        <div class="stat-card c-red">
          <div class="stat-val" id="ov-recycle">—</div>
          <div class="stat-label">Papelera</div>
        </div>
      </div>
      <div class="info-grid">
        <div class="info-panel">
          <h3>Imagen</h3>
          <div class="kv-row"><span class="kv-key">Fichero</span><span class="kv-val" id="kv-filename">—</span></div>
          <div class="kv-row"><span class="kv-key">Tamaño</span><span class="kv-val" id="kv-size">—</span></div>
          <div class="kv-row"><span class="kv-key">Tipo</span><span class="kv-val" id="kv-imgtype">—</span></div>
          <div class="kv-row"><span class="kv-key">Entropía</span><span class="kv-val" id="kv-entropy">—</span></div>
          <div class="kv-row"><span class="kv-key">Backend</span><span class="kv-val" id="kv-backend">—</span></div>
          <div class="kv-row"><span class="kv-key">SO detectado</span><span class="kv-val" id="kv-os">—</span></div>
        </div>
        <div class="info-panel">
          <h3>Hashes</h3>
          <div class="kv-row"><span class="kv-key">MD5</span><span class="kv-val mono" id="kv-md5">—</span></div>
          <div class="kv-row"><span class="kv-key">SHA1</span><span class="kv-val mono" id="kv-sha1">—</span></div>
          <div class="kv-row"><span class="kv-key">SHA256</span><span class="kv-val mono" id="kv-sha256">—</span></div>
          <div class="kv-row"><span class="kv-key">Nota</span><span class="kv-val" id="kv-hash-note">—</span></div>
        </div>
      </div>
      <div class="info-grid">
        <div class="info-panel">
          <h3>Info del filesystem</h3>
          <div class="pre-box" id="kv-fsstat">—</div>
        </div>
        <div class="info-panel">
          <h3>img_stat</h3>
          <div class="pre-box" id="kv-imgstat">—</div>
        </div>
      </div>
    </div>
  </section>

  {{-- FILES --}}
  <section class="section" id="s-files">
    <div class="s-header">
      <div class="s-title">Árbol de ficheros</div>
      <span class="tbl-count" id="files-count"></span>
    </div>
    <div class="s-body">
      <div class="tbl-toolbar">
        <input class="tbl-search" id="files-search" placeholder="Buscar por nombre o inode..." oninput="filterFiles()">
        <select class="tbl-filter" id="files-filter" onchange="filterFiles()">
          <option value="">Todos</option>
          <option value="file">Ficheros</option>
          <option value="dir">Directorios</option>
          <option value="deleted">Eliminados</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th onclick="sortFiles('type')">Tipo</th>
              <th onclick="sortFiles('name')">Nombre / Ruta</th>
              <th onclick="sortFiles('inode')">Inode</th>
              <th onclick="sortFiles('size')">Tamaño</th>
              <th onclick="sortFiles('mtime')">Modificado</th>
            </tr>
          </thead>
          <tbody id="files-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- DELETED --}}
  <section class="section" id="s-deleted">
    <div class="s-header">
      <div class="s-title">Ficheros eliminados</div>
      <span class="tbl-count" id="del-count"></span>
    </div>
    <div class="s-body">
      <div class="tbl-toolbar">
        <input class="tbl-search" id="del-search" placeholder="Buscar..." oninput="filterDeleted()">
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Nombre</th><th>Inode</th><th>Ruta original</th>
          </tr></thead>
          <tbody id="del-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- FILE TYPES --}}
  <section class="section" id="s-filetypes">
    <div class="s-header"><div class="s-title">Clasificación por tipo de fichero</div></div>
    <div class="s-body">
      <div class="ft-grid" id="ft-grid"></div>
    </div>
  </section>

  {{-- BROWSER HISTORY --}}
  <section class="section" id="s-history">
    <div class="s-header">
      <div class="s-title">Historial de navegación</div>
      <span class="tbl-count" id="hist-count"></span>
    </div>
    <div class="s-body">
      <div id="hist-note"></div>
      <div class="tbl-toolbar">
        <input class="tbl-search" id="hist-search" placeholder="Buscar URL o título..." oninput="filterHistory()">
        <select class="tbl-filter" id="hist-browser" onchange="filterHistory()">
          <option value="">Todos los navegadores</option>
        </select>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th onclick="sortHistory('browser')">Navegador</th>
            <th onclick="sortHistory('time')">Fecha/Hora</th>
            <th onclick="sortHistory('url')">URL</th>
            <th onclick="sortHistory('title')">Título</th>
            <th onclick="sortHistory('count')">Visitas</th>
          </tr></thead>
          <tbody id="hist-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- DOWNLOADS --}}
  <section class="section" id="s-downloads">
    <div class="s-header">
      <div class="s-title">Descargas del navegador</div>
      <span class="tbl-count" id="dl-count"></span>
    </div>
    <div class="s-body">
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Fecha</th><th>Ruta</th><th>Tamaño</th></tr></thead>
          <tbody id="dl-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- WEB SEARCHES --}}
  <section class="section" id="s-searches">
    <div class="s-header">
      <div class="s-title">Búsquedas web</div>
      <span class="tbl-count" id="srch-count"></span>
    </div>
    <div class="s-body">
      <div class="str-grid" id="srch-grid"></div>
    </div>
  </section>

  {{-- LNK --}}
  <section class="section" id="s-lnk">
    <div class="s-header">
      <div class="s-title">Accesos directos (LNK)</div>
      <span class="tbl-count" id="lnk-count"></span>
    </div>
    <div class="s-body">
      <div class="info-note">Los ficheros LNK de Windows guardan la ruta al fichero original, timestamps y metadatos del sistema origen.</div>
      <div class="tbl-toolbar">
        <input class="tbl-search" id="lnk-search" placeholder="Buscar..." oninput="filterLnk()">
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Estado</th><th onclick="sortLnk('name')">Nombre LNK</th>
            <th onclick="sortLnk('mtime')">Modificado</th><th>Inode</th>
            <th>Acciones</th>
          </tr></thead>
          <tbody id="lnk-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- PREFETCH --}}
  <section class="section" id="s-prefetch">
    <div class="s-header">
      <div class="s-title">Prefetch — Programas ejecutados</div>
      <span class="tbl-count" id="pf-count"></span>
    </div>
    <div class="s-body">
      <div class="info-note">Los ficheros Prefetch de Windows (C:\Windows\Prefetch) registran cada programa ejecutado.</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th onclick="sortPf('exe')">Programa</th>
            <th onclick="sortPf('mtime')">Última ejecución</th>
            <th>Fichero Prefetch</th><th>Inode</th><th>Acciones</th>
          </tr></thead>
          <tbody id="pf-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- REGISTRY HIVES --}}
  <section class="section" id="s-registry">
    <div class="s-header"><div class="s-title">Hives del registro de Windows</div></div>
    <div class="s-body">
      <div class="info-note">Ficheros de registro encontrados en la imagen. Requieren python-registry para análisis completo.</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr><th>Hive</th><th>Ruta</th><th>Tamaño</th><th>Inode</th><th>Acciones</th></tr></thead>
          <tbody id="reg-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- USERS --}}
  <section class="section" id="s-users">
    <div class="s-header">
      <div class="s-title">Cuentas de usuario detectadas</div>
    </div>
    <div class="s-body">
      <div class="user-grid" id="user-grid"></div>
    </div>
  </section>

  {{-- SUSPICIOUS --}}
  <section class="section" id="s-suspicious">
    <div class="s-header">
      <div class="s-title">Análisis de amenazas — Ficheros sospechosos</div>
      <span class="tbl-count" id="sus-count"></span>
    </div>
    <div class="s-body">
      <div class="tbl-toolbar">
        <input class="tbl-search" id="sus-search" placeholder="Buscar..." oninput="filterSuspicious()">
      </div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Estado</th><th onclick="sortSus('name')">Nombre</th>
            <th>Motivo</th><th onclick="sortSus('mtime')">Modificado</th>
            <th>Inode</th><th>Acciones</th>
          </tr></thead>
          <tbody id="sus-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- STRINGS --}}
  <section class="section" id="s-strings">
    <div class="s-header"><div class="s-title">Indicadores de Compromiso (IoC)</div></div>
    <div class="s-body">
      <div class="tbl-toolbar">
        <input class="tbl-search" id="str-search" placeholder="Filtrar strings..." oninput="filterStrings()">
      </div>
      <div class="tabs" id="str-tabs">
        <button class="tab active" onclick="switchStrTab('urls')" id="stab-urls">URLs <span class="tab-count" id="stc-urls">0</span></button>
        <button class="tab" onclick="switchStrTab('emails')" id="stab-emails">Emails <span class="tab-count" id="stc-emails">0</span></button>
        <button class="tab" onclick="switchStrTab('ips')" id="stab-ips">IPs <span class="tab-count" id="stc-ips">0</span></button>
        <button class="tab" onclick="switchStrTab('paths')" id="stab-paths">Rutas <span class="tab-count" id="stc-paths">0</span></button>
        <button class="tab" onclick="switchStrTab('other')" id="stab-other">Strings <span class="tab-count" id="stc-other">0</span></button>
      </div>
      <div class="tab-panel active" id="spanel-urls"><div class="str-grid" id="sg-urls"></div></div>
      <div class="tab-panel" id="spanel-emails"><div class="str-grid" id="sg-emails"></div></div>
      <div class="tab-panel" id="spanel-ips"><div class="str-grid" id="sg-ips"></div></div>
      <div class="tab-panel" id="spanel-paths"><div class="str-grid" id="sg-paths"></div></div>
      <div class="tab-panel" id="spanel-other"><div class="str-grid" id="sg-other"></div></div>
    </div>
  </section>

  {{-- TIMELINE --}}
  <section class="section" id="s-timeline">
    <div class="s-header">
      <div class="s-title">Timeline de actividad</div>
      <span class="tbl-count" id="tl-count"></span>
    </div>
    <div class="s-body">
      <div class="tbl-toolbar">
        <input class="tbl-search" id="tl-search" placeholder="Filtrar..." oninput="filterTimeline()">
        <select class="tbl-filter" id="tl-filter" onchange="filterTimeline()">
          <option value="">Todos</option>
          <option value="file">Ficheros</option>
          <option value="dir">Directorios</option>
          <option value="deleted">Eliminados</option>
        </select>
      </div>
      <div id="tl-body" style="max-height:calc(100vh - 260px);overflow-y:auto"></div>
    </div>
  </section>

  {{-- HEX VIEWER --}}
  <section class="section" id="s-hex">
    <div class="s-header"><div class="s-title">Visor hexadecimal</div></div>
    <div class="s-body">
      <div class="hex-toolbar">
        <input class="hex-input" id="hex-inode" placeholder="Inode..." type="number">
        <input class="hex-input" id="hex-bytes" placeholder="Bytes (max 65536)" type="number" value="4096">
        <button class="btn btn-primary" onclick="loadHex()">Cargar</button>
        <span style="font-size:12px;color:var(--muted)" id="hex-info"></span>
      </div>
      <div id="hex-display"><div class="hex-empty">Introduce un inode y pulsa Cargar</div></div>
    </div>
  </section>

  {{-- INODE INSPECTOR --}}
  <section class="section" id="s-inode">
    <div class="s-header"><div class="s-title">Inspector de inode</div></div>
    <div class="s-body">
      <div class="tbl-toolbar" style="margin-bottom:16px">
        <input class="tbl-search" id="inode-input" placeholder="Número de inode..." type="number">
        <button class="btn btn-primary" onclick="inspectInode()">Inspeccionar</button>
      </div>
      <div class="pre-box" id="inode-out" style="max-height:none">Introduce un inode</div>
    </div>
  </section>

  {{-- PARTITIONS --}}
  <section class="section" id="s-partitions">
    <div class="s-header"><div class="s-title">Volumen y tabla de particiones</div></div>
    <div class="s-body">
      <div class="part-box" id="part-mmls">—</div>
    </div>
  </section>

  {{-- RECYCLE BIN --}}
  <section class="section" id="s-recycle">
    <div class="s-header">
      <div class="s-title">Papelera de reciclaje</div>
      <span class="tbl-count" id="recycle-count"></span>
    </div>
    <div class="s-body">
      <div class="info-note">$I: metadatos del fichero original — contiene nombre original, tamaño y fecha exacta de borrado. $R: contenido recuperable del fichero borrado. La presencia de ficheros en la papelera prueba que el usuario borró deliberadamente esos ficheros. Exporta con inode para recuperar el contenido con herramientas forenses.</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Tipo</th><th>Que es</th><th>Nombre en papelera</th><th>Ruta original</th>
            <th>Tamaño</th><th>Eliminado el</th><th>Inode</th><th>Acciones</th>
          </tr></thead>
          <tbody id="recycle-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- STARTUP ITEMS --}}
  <section class="section" id="s-startup">
    <div class="s-header">
      <div class="s-title">Elementos de inicio automático</div>
      <span class="tbl-count" id="startup-count"></span>
    </div>
    <div class="s-body">
      <div class="warn-note">REVISAR TODOS: Los ejecutables en ubicaciones de inicio se lanzan en cada arranque del sistema. Es el mecanismo de persistencia mas comun en malware. Cualquier ejecutable desconocido aqui es sospechoso. Compara con listas de aplicaciones legitimas conocidas.</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Riesgo</th><th>Nombre</th><th>Extension</th><th>Ruta completa</th>
            <th>Tamaño</th><th>Modificado</th><th>Inode</th><th>Acciones</th>
          </tr></thead>
          <tbody id="startup-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- EVENT LOGS --}}
  <section class="section" id="s-events">
    <div class="s-header">
      <div class="s-title">Registros de eventos del sistema</div>
      <span class="tbl-count" id="events-count"></span>
    </div>
    <div class="s-body">
      <div class="info-note">Ficheros .evtx de Windows. Cada canal registra un tipo de actividad: Security (4624=login OK, 4625=fallo login, 4720=cuenta creada), System (arranques, servicios), PowerShell (ejecucion de comandos), Sysmon (actividad avanzada). Un fichero eliminado indica borrado deliberado de trazas.</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Estado</th><th>Canal / Tipo</th><th>Fichero .evtx</th>
            <th>Relevancia forense</th><th>Tamaño</th><th>Modificado</th><th>Inode</th><th>Acciones</th>
          </tr></thead>
          <tbody id="events-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- EMAIL FILES --}}
  <section class="section" id="s-email">
    <div class="s-header">
      <div class="s-title">Artefactos de correo electrónico</div>
      <span class="tbl-count" id="email-count"></span>
    </div>
    <div class="s-body">
      <div class="info-note">Buzones y mensajes de correo detectados. Los ficheros PST/OST de Outlook y MBOX de Thunderbird pueden contener comunicaciones completas del usuario.</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Estado</th><th>Nombre</th><th>Formato</th>
            <th>Ruta</th><th>Tamaño</th><th>Modificado</th><th>Inode</th><th>Acciones</th>
          </tr></thead>
          <tbody id="email-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- NETWORK ARTIFACTS --}}
  <section class="section" id="s-network">
    <div class="s-header">
      <div class="s-title">Artefactos de red</div>
      <span class="tbl-count" id="network-count"></span>
    </div>
    <div class="s-body">
      <div class="info-note">Ficheros de configuracion de red. Los perfiles WiFi (.xml en Windows) contienen SSIDs y a veces passwords en texto plano. El fichero hosts puede revelar redireccionamiento de dominios. Los ficheros SSH (known_hosts, authorized_keys) revelan conexiones remotas establecidas.</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Nombre</th><th>Que contiene / Por que importa</th><th>Ruta</th>
            <th>Tamaño</th><th>Modificado</th><th>Inode</th><th>Acciones</th>
          </tr></thead>
          <tbody id="network-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- USB TRACES --}}
  <section class="section" id="s-usb">
    <div class="s-header">
      <div class="s-title">Trazas de dispositivos USB</div>
      <span class="tbl-count" id="usb-count"></span>
    </div>
    <div class="s-body">
      <div class="info-note">Evidencias de dispositivos USB conectados. setupapi.dev.log registra cada dispositivo instalado con timestamp y GUID. La ruta usbstor/ en el registro guarda el VID/PID, numero de serie y primera/ultima conexion. Esto puede probar exfiltracion de datos via dispositivo externo.</div>
      <div class="tbl-wrap">
        <table>
          <thead><tr>
            <th>Nombre</th><th>Que prueba</th><th>Ruta</th><th>Tamaño</th><th>Modificado</th><th>Inode</th><th>Acciones</th>
          </tr></thead>
          <tbody id="usb-body"></tbody>
        </table>
      </div>
    </div>
  </section>

  {{-- REPORT --}}
  <section class="section" id="s-report">
    <div class="s-header">
      <div class="s-title">Informe forense</div>
      <div style="display:flex;gap:8px">
        <button class="btn" onclick="copyReport()">Copiar</button>
        <button class="btn btn-primary" onclick="downloadReport()">Descargar</button>
      </div>
    </div>
    <div class="s-body">
      <div id="report-output">El informe se genera cuando hay un caso abierto.</div>
    </div>
  </section>

</main>
</div>

<div id="toasts"></div>

<script>window.BACKEND_URL = '{{ rtrim(config("forensic.backend_url"), "/") }}';</script>
<script src="{{ asset('js/analyzer.js') }}" defer></script>
</body>
</html>
