# CaseAnalyzer

Analizador forense de imágenes de disco. Extrae sistema de archivos, archivos eliminados, strings categorizados, hashes criptográficos y metadatos de inodes.

Formatos soportados: `.dd` · `.img` · `.raw` · `.iso` · `.E01` · `.001` · `.bin`

## Requisitos previos

| Componente | Versión mínima | Descarga |
|------------|----------------|---------|
| PHP        | 8.3            | https://windows.php.net/download |
| Composer   | 2.x            | https://getcomposer.org |
| Node.js    | 20+            | https://nodejs.org |
| Python     | 3.11           | https://www.python.org/downloads/release/python-3119 |

> **Importante:** Usa Python 3.11 específicamente. pytsk3 no tiene wheel precompilado para Python 3.12+.

---

## Instalación (primera vez)

### 1. Dependencias PHP y assets

```bat
composer install
copy .env.example .env
php artisan key:generate
npm install && npm run build
```

### 2. Entorno virtual Python

```bat
py -3.11 -m venv .venv
.venv\Scripts\pip install -r LeerDD\requirements.txt
.venv\Scripts\pip install pytsk3
```

### 3. Herramientas forenses vía WSL (para análisis completo con E01/EWF)

Abre PowerShell como Administrador y ejecuta:

```
wsl --install -d Ubuntu
```

Cuando se abra la terminal de Ubuntu, crea tu usuario y ejecuta:

```bash
sudo apt-get update -qq && sudo apt-get install -y sleuthkit ewf-tools
```

Cierra la terminal de Ubuntu. El arrancar.bat detectará WSL automáticamente.

---

## Iniciar la aplicación

Haz doble clic en **`arrancar.bat`** o ejecútalo desde la terminal:

```bat
arrancar.bat
```

Esto arranca automáticamente:
- Backend Python (FastAPI) en http://127.0.0.1:8001
- Frontend Laravel en http://127.0.0.1:8000

Abre http://127.0.0.1:8000 en el navegador.

---

## Arquitectura

```
Navegador → Laravel :8000 → Python FastAPI :8001
```

- **Frontend**: Laravel 13 + Blade + Tailwind CSS
- **Motor forense**: Python FastAPI con pytsk3 / SleuthKit vía WSL

### Backends forenses (por orden de prioridad)

1. **pytsk3** — Librería Python para Windows, sin dependencias externas.
2. **WSL + sleuthkit** — Fallback vía WSL. Necesario para imágenes E01/EWF.

---

## Funciones

- Filesystem completo (archivos, directorios, inodes)
- Detección y listado de archivos eliminados
- Extracción de strings categorizados (URLs, emails, rutas, IPs)
- Hashes MD5 / SHA1 / SHA256
- Detección de tipo de imagen y cálculo de entropía
- Tabla de particiones (MBR / GPT)
- Inspector de inodes
- Exportación JSON / CSV / TXT

---

## Variables de entorno (.env)

| Variable | Descripción | Por defecto |
|----------|-------------|-------------|
| `FORENSIC_BACKEND_URL` | URL del backend Python | `http://localhost:8001` |
| `FORENSIC_BACKEND_PORT` | Puerto del backend Python | `8001` |
| `FORENSIC_TIMEOUT` | Timeout análisis en segundos | `7260` |

---

## Estructura del proyecto

```
CaseAnalyzer/
├── arrancar.bat                              # Lanzador Windows
├── LeerDD/
│   ├── main.py                              # FastAPI server
│   ├── analyzer.py                          # Motor forense
│   └── requirements.txt                     # Dependencias Python
├── app/
│   ├── Http/Controllers/CaseController.php
│   ├── Http/Middleware/SecurityHeaders.php
│   └── Console/Commands/ServeCommand.php
└── resources/views/analyzer.blade.php       # Interfaz
```

---

## Seguridad

- CSP, X-Frame-Options, HSTS y demás headers configurados en `SecurityHeaders.php`
- Rate limiting en todos los endpoints
- Sin autenticación por defecto — añade middleware de auth para despliegue público

---

## Imágenes forenses de prueba

https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html
