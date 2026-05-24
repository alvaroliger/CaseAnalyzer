"""
main.py — CaseAnalyzer Backend v4.1 (FastAPI)
"""

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from typing import List
import shutil, os, uuid, platform, logging, time, asyncio, sys, json, re, base64, tempfile
from pathlib import Path
from analyzer import (
    get_inode_metadata, _read_file_bytes, _gather_split_parts,
    BACKEND, HAS_PYTSK3, HAS_TSK_FLS, HAS_WSL, HAS_7ZIP
)

# ─── Directorios ──────────────────────────────────────────────────────────────
# Las imágenes subidas van fuera del proyecto para no ocupar espacio en el workspace.
# Se puede sobreescribir con la variable de entorno CASEANALYZER_UPLOAD_DIR.
_PROJECT_ROOT   = Path(__file__).parent.parent
_DEFAULT_UPLOADS = Path(tempfile.gettempdir()) / "CaseAnalyzer" / "uploads"
UPLOAD_DIR      = Path(os.environ.get("CASEANALYZER_UPLOAD_DIR", str(_DEFAULT_UPLOADS)))
LOG_DIR         = _PROJECT_ROOT / "logs"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_DIR / "backend.log", encoding="utf-8"),
    ]
)
logger = logging.getLogger("caseanalyzer")
logger.info("Backend iniciado | BACKEND=%s pytsk3=%s tsk=%s wsl=%s 7zip=%s",
            BACKEND, HAS_PYTSK3, HAS_TSK_FLS, HAS_WSL, HAS_7ZIP)
logger.info("UPLOAD_DIR=%s  LOG_DIR=%s", UPLOAD_DIR, LOG_DIR)

app = FastAPI(title="CaseAnalyzer API", version="4.1.1",
              docs_url="/docs", redoc_url="/redoc")

# Compresión automática de respuestas >= 1 KB
app.add_middleware(GZipMiddleware, minimum_size=1024)

_raw_origins = os.environ.get(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000,http://localhost:8001,http://127.0.0.1:8001",
)
_ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-TOKEN"])

_WORKER          = Path(__file__).parent / "analyze_worker.py"
ANALYSIS_TIMEOUT = int(os.environ.get("ANALYSIS_TIMEOUT", 7200))
MAX_FILES        = int(os.environ.get("MAX_FILES", 5000))
MAX_CONCURRENT   = int(os.environ.get("MAX_CONCURRENT_ANALYSES", 2))
UPLOAD_TTL_HOURS = int(os.environ.get("UPLOAD_TTL_HOURS", 24))
ALLOWED_EXTS     = {".dd", ".img", ".raw", ".iso", ".e01", ".001", ".bin", ".7z"}
_MULTIPART_EXT   = re.compile(r'^\.\d{3}$')

# Semáforo para limitar análisis simultáneos y evitar agotamiento de memoria
_analysis_sem: asyncio.Semaphore | None = None


def _cleanup_expired_uploads() -> int:
    """Elimina uploads e imágenes de análisis cuyo mtime supera UPLOAD_TTL_HOURS."""
    cutoff = time.time() - UPLOAD_TTL_HOURS * 3600
    removed = 0
    try:
        for f in UPLOAD_DIR.iterdir():
            if f.name == ".gitkeep":
                continue
            if f.is_file() and f.stat().st_mtime < cutoff:
                f.unlink(missing_ok=True)
                removed += 1
                log = LOG_DIR / f"{f.stem}.log"
                if log.exists():
                    log.unlink(missing_ok=True)
    except Exception as e:
        logger.warning("Error durante limpieza automática: %s", e)
    if removed:
        logger.info("Limpieza automática: %d fichero(s) eliminado(s) (TTL=%dh)", removed, UPLOAD_TTL_HOURS)
    return removed


async def _periodic_cleanup():
    while True:
        await asyncio.sleep(3600)
        _cleanup_expired_uploads()


@app.on_event("startup")
async def _startup():
    global _analysis_sem
    _analysis_sem = asyncio.Semaphore(MAX_CONCURRENT)
    _cleanup_expired_uploads()
    asyncio.create_task(_periodic_cleanup())


def _ext_allowed(ext: str) -> bool:
    return ext in ALLOWED_EXTS or bool(_MULTIPART_EXT.match(ext))


def _find_image_for_id(file_id: str) -> Path | None:
    """Devuelve la ruta de imagen (.001 o primera parte) cuyo stem coincide con file_id."""
    try:
        candidates = sorted(f for f in UPLOAD_DIR.iterdir() if f.stem == file_id)
        return candidates[0] if candidates else None
    except Exception:
        return None


def _find_split_parts_for_id(file_id: str) -> list[str] | None:
    """Devuelve todas las partes split de una imagen, o None si no es split."""
    img = _find_image_for_id(file_id)
    if not img:
        return None
    parts = _gather_split_parts(str(img))
    return parts if len(parts) > 1 else None


async def _run_analysis(image_path: Path, log_path: Path) -> dict:
    """Ejecuta el worker en subproceso con streaming de stderr y timeout global."""
    result_path = image_path.with_suffix(".result.json")
    _t0 = time.monotonic()

    def wlog(msg: str):
        elapsed = time.monotonic() - _t0
        line = f"{time.strftime('%H:%M:%S')} +{elapsed:6.1f}s  {msg}\n"
        logger.info(msg)
        try:
            with open(log_path, "a", encoding="utf-8") as lf:
                lf.write(line)
        except Exception:
            pass

    wlog("=== INICIO ANÁLISIS ===")
    wlog(f"Imagen:  {image_path}")
    wlog(f"Worker:  {_WORKER}")
    wlog(f"Python:  {sys.executable}")
    wlog(f"Backend: {BACKEND} | pytsk3={HAS_PYTSK3} | tsk={HAS_TSK_FLS} | wsl={HAS_WSL} | 7zip={HAS_7ZIP}")

    assert _analysis_sem is not None, "Semáforo no inicializado"
    async with _analysis_sem:
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, str(_WORKER), str(image_path), str(result_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
            )
            wlog(f"Worker PID {proc.pid} iniciado (timeout={ANALYSIS_TIMEOUT}s)")

            async def _stream_stderr():
                async for line in proc.stderr:
                    text = line.decode(errors="replace").rstrip()
                    if text:
                        wlog(f"  [worker] {text}")

            try:
                await asyncio.wait_for(
                    asyncio.gather(proc.wait(), _stream_stderr()),
                    timeout=ANALYSIS_TIMEOUT
                )
            except asyncio.TimeoutError:
                wlog(f"ERROR: Worker superó {ANALYSIS_TIMEOUT}s — matando PID {proc.pid}")
                try:
                    proc.kill()
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except Exception as ke:
                    wlog(f"  No se pudo matar worker: {ke}")
                wlog("=== TIMEOUT ===")
                raise HTTPException(
                    504,
                    f"Análisis superó {ANALYSIS_TIMEOUT}s. Revisa el log: {log_path}"
                )

            exit_code = proc.returncode
            wlog(f"Worker finalizado con código {exit_code}")

            if not result_path.exists():
                wlog("ERROR: Worker no produjo fichero resultado")
                wlog("=== FIN (sin resultado) ===")
                raise HTTPException(500, f"Worker no produjo resultado. Revisa el log: {log_path}")

            result = json.loads(result_path.read_text(encoding="utf-8"))

            if exit_code != 0:
                wlog(f"ADVERTENCIA: Worker salió con error (código {exit_code}) — resultado parcial")

            wlog(f"Ficheros: {result.get('total_files',0)} | Eliminados: {result.get('total_deleted',0)}")
            wlog("=== FIN ANÁLISIS OK ===")
            return result

        finally:
            result_path.unlink(missing_ok=True)


def _truncate_files(result: dict) -> dict:
    """Limita la lista de ficheros a MAX_FILES in-place y devuelve el resultado."""
    if len(result.get("files", [])) > MAX_FILES:
        result["files_truncated"] = len(result["files"]) - MAX_FILES
        result["files"] = result["files"][:MAX_FILES]
    return result


@app.get("/health")
async def health():
    return {
        "status": "ok", "platform": platform.system(), "arch": platform.machine(),
        "python": platform.python_version(), "backend": BACKEND,
        "capabilities": {
            "pytsk3": HAS_PYTSK3, "tsk_binaries": bool(HAS_TSK_FLS),
            "wsl": HAS_WSL, "7zip": HAS_7ZIP,
        },
        "upload_dir": str(UPLOAD_DIR), "log_dir": str(LOG_DIR), "version": "4.1.1",
        "max_concurrent": MAX_CONCURRENT, "upload_ttl_hours": UPLOAD_TTL_HOURS,
    }


def _is_volume_part(primary_ext: str, extra_ext: str) -> bool:
    return bool(_MULTIPART_EXT.match(primary_ext) and _MULTIPART_EXT.match(extra_ext))


@app.post("/analyze")
async def analyze(files: List[UploadFile] = File(...)):
    if not files:
        raise HTTPException(400, "No se recibió ningún archivo.")

    files = sorted(files, key=lambda f: f.filename)
    primary = files[0]

    suffix = Path(primary.filename).suffix.lower()
    if not _ext_allowed(suffix):
        raise HTTPException(400, f"Extensión '{suffix}' no soportada.")

    file_id   = str(uuid.uuid4())
    save_path = UPLOAD_DIR / f"{file_id}{suffix}"
    log_path  = LOG_DIR    / f"{file_id}.log"
    t0        = time.monotonic()
    all_saved: list[Path] = []
    extra_paths: list[Path] = []
    separate_images: list[tuple[Path, str]] = []

    logger.info("Análisis iniciado: %s  id: %s", primary.filename, file_id)
    if len(files) > 1:
        logger.info("Archivos adicionales: %s", [f.filename for f in files[1:]])

    try:
        with open(save_path, "wb") as f:
            shutil.copyfileobj(primary.file, f)
        all_saved.append(save_path)
        logger.info("Imagen guardada: %s (%.1f MB)",
                    save_path, save_path.stat().st_size / 1_048_576)

        for extra in files[1:]:
            extra_suffix = Path(extra.filename).suffix.lower()
            if not _ext_allowed(extra_suffix):
                logger.warning("Archivo con extensión no soportada ignorado: %s", extra.filename)
                continue

            if _is_volume_part(suffix, extra_suffix):
                extra_path = UPLOAD_DIR / f"{file_id}{extra_suffix}"
                with open(extra_path, "wb") as f:
                    shutil.copyfileobj(extra.file, f)
                extra_paths.append(extra_path)
                all_saved.append(extra_path)
                logger.info("Volumen parte guardado: %s (%.1f MB)",
                            extra_path, extra_path.stat().st_size / 1_048_576)
            else:
                sep_id   = str(uuid.uuid4())
                sep_path = UPLOAD_DIR / f"{sep_id}{extra_suffix}"
                with open(sep_path, "wb") as f:
                    shutil.copyfileobj(extra.file, f)
                separate_images.append((sep_path, extra.filename))
                all_saved.append(sep_path)
                logger.info("Imagen separada guardada: %s (%.1f MB)",
                            sep_path, sep_path.stat().st_size / 1_048_576)

        # ── Análisis primario ────────────────────────────────────────────────
        result = await _run_analysis(save_path, log_path)
        result["filename"]  = primary.filename
        result["file_id"]   = file_id
        result["log_path"]  = str(log_path)
        result["file_size"] = save_path.stat().st_size if save_path.exists() else 0
        _truncate_files(result)

        # ── Análisis de imágenes separadas EN PARALELO ───────────────────────
        if separate_images:
            logger.info("Analizando %d imagen(es) separada(s) en paralelo...", len(separate_images))

            async def _analyze_sep(sep_path: Path, sep_name: str) -> dict:
                sep_log = LOG_DIR / f"{sep_path.stem}.log"
                res     = await _run_analysis(sep_path, sep_log)
                res["filename"]  = sep_name
                res["file_id"]   = sep_path.stem
                res["log_path"]  = str(sep_log)
                res["file_size"] = sep_path.stat().st_size if sep_path.exists() else 0
                _truncate_files(res)
                logger.info("Imagen separada completada: %s — %d archivos",
                            sep_name, res.get("total_files", 0))
                return res

            sep_results = await asyncio.gather(
                *[_analyze_sep(p, n) for p, n in separate_images],
                return_exceptions=True,
            )
            # Filtrar excepciones (no abortar si falla una imagen secundaria)
            result["additional_images"] = [
                r for r in sep_results if isinstance(r, dict)
            ]
            errors = [str(r) for r in sep_results if isinstance(r, Exception)]
            if errors:
                logger.warning("Errores en imágenes secundarias: %s", errors)
                result["additional_images_errors"] = errors

        elapsed = round(time.monotonic() - t0, 2)
        logger.info("Completado en %.2fs — %d archivos, %d eliminados",
                    elapsed, result.get("total_files", 0), result.get("total_deleted", 0))
        return JSONResponse(content=result)

    except HTTPException:
        for p in all_saved:
            p.unlink(missing_ok=True)
        raise
    except MemoryError:
        for p in all_saved:
            p.unlink(missing_ok=True)
        raise HTTPException(500, "Imagen demasiado grande para procesar en memoria")
    except Exception as e:
        for p in all_saved:
            p.unlink(missing_ok=True)
        logger.error("Error inesperado: %s", e, exc_info=True)
        raise HTTPException(500, f"Error analizando imagen: {e}")


@app.get("/logs/{file_id}")
async def get_log(file_id: str):
    if not re.match(r'^[a-f0-9\-]{1,40}$', file_id, re.I):
        raise HTTPException(400, "file_id inválido")
    log_path = LOG_DIR / f"{file_id}.log"
    if not log_path.exists():
        raise HTTPException(404, "Log no encontrado")
    return JSONResponse({"log": log_path.read_text(encoding="utf-8", errors="replace")})


@app.get("/file/{file_id}/{inode}")
async def get_file(file_id: str, inode: int, offset: int = 0, max_bytes: int = 65536):
    if not re.match(r'^[a-f0-9\-]{1,40}$', file_id, re.I):
        raise HTTPException(400, "file_id inválido")
    max_bytes = min(max_bytes, 10 * 1024 * 1024)

    image_path = _find_image_for_id(file_id)
    if not image_path:
        raise HTTPException(404, "Imagen no encontrada")

    split_parts = _find_split_parts_for_id(file_id)
    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(
        None, _read_file_bytes, str(image_path), inode, max_bytes, offset, max_bytes, split_parts
    )
    if data is None:
        raise HTTPException(404, "No se pudo leer el fichero (inode no encontrado o backend sin soporte)")

    return JSONResponse(content={
        "inode": inode, "size": len(data),
        "content_b64": base64.b64encode(data).decode(),
    })


@app.get("/metadata/{file_id}/{inode}")
async def inode_meta(file_id: str, inode: str, offset: int = None):
    if not re.match(r'^[a-f0-9\-]{1,40}$', file_id, re.I):
        raise HTTPException(400, "file_id inválido")
    if not re.match(r'^\d{1,10}$', inode):
        raise HTTPException(400, "inode inválido")

    image_path = _find_image_for_id(file_id)
    if not image_path:
        raise HTTPException(404, "Imagen no encontrada")

    split_parts = _find_split_parts_for_id(file_id)
    return JSONResponse(content=get_inode_metadata(str(image_path), inode, offset, split_parts))


@app.delete("/cleanup/{file_id}")
async def cleanup(file_id: str):
    if not re.match(r'^[a-f0-9\-]{1,40}$', file_id, re.I):
        raise HTTPException(400, "file_id inválido")
    deleted = []
    for f in UPLOAD_DIR.iterdir():
        if f.stem == file_id:
            f.unlink(missing_ok=True)
            deleted.append(f.name)
    lp = LOG_DIR / f"{file_id}.log"
    if lp.exists():
        lp.unlink(missing_ok=True)
        deleted.append(lp.name)
    return {"deleted": deleted}


@app.get("/")
async def root():
    return {"app": "CaseAnalyzer API", "version": "4.1.1",
            "docs": "/docs", "backend": BACKEND}
