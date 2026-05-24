"""
analyze_worker.py — Subproceso aislado por main.py.
Escribe resultado JSON en el fichero indicado, sale con código 0.
Si falla, escribe JSON de error y sale con código 1.
Todos los logs van a stderr (visibles en la consola del backend).
"""
import sys
import json
import traceback
import time
import os
import threading

def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [WORKER] {msg}", file=sys.stderr, flush=True)


def _start_watchdog(interval: int = 10):
    """Hilo daemon que imprime heartbeat cada `interval` segundos.
    Permite detectar en el log cuándo el proceso se cuelga sin emitir nada."""
    t0 = time.monotonic()
    def _run():
        while True:
            time.sleep(interval)
            elapsed = time.monotonic() - t0
            print(f"[{time.strftime('%H:%M:%S')}] [WATCHDOG] vivo +{elapsed:.0f}s",
                  file=sys.stderr, flush=True)
    t = threading.Thread(target=_run, daemon=True)
    t.start()

def main():
    if len(sys.argv) != 3:
        print("[WORKER] ERROR: uso: analyze_worker.py <image_path> <result_path>", file=sys.stderr)
        sys.exit(2)

    image_path  = sys.argv[1]
    result_path = sys.argv[2]

    _start_watchdog(interval=10)
    log(f"Iniciando análisis de: {image_path}")
    log(f"Resultado se guardará en: {result_path}")

    try:
        size = os.path.getsize(image_path)
        log(f"Tamaño de imagen: {size:,} bytes ({size / 1_048_576:.1f} MB)")
    except Exception as e:
        log(f"No se pudo leer tamaño: {e}")

    t0 = time.monotonic()
    try:
        log("Importando módulo analyzer...")
        from analyzer import analyze_image, BACKEND, HAS_PYTSK3, HAS_TSK_FLS, HAS_WSL
        log(f"Backend disponible: {BACKEND} | pytsk3={HAS_PYTSK3} | tsk={HAS_TSK_FLS} | wsl={HAS_WSL}")

        if BACKEND == "none":
            log("[WARN] No hay backend forense disponible.")
            log("  Opciones para habilitar analisis real:")
            log("  - pip install pytsk3")
            log("  - wsl --install  (luego: wsl -e sudo apt install sleuthkit)")

        log("Iniciando analyze_image()...")
        result = analyze_image(image_path, progress_cb=log)

        elapsed = time.monotonic() - t0
        log(f"analyze_image() completado en {elapsed:.1f}s")
        log(f"Ficheros encontrados: {result.get('total_files', 0)}")
        log(f"Ficheros eliminados:  {result.get('total_deleted', 0)}")
        log(f"Backend usado:        {result.get('backend', '?')}")

        if result.get("error"):
            log(f"[WARN] El analisis devolvio un error: {result['error'][:300]}")

        log("Escribiendo resultado JSON...")
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False)
        log(f"Resultado escrito. Saliendo con código 0.")
        sys.exit(0)

    except Exception:
        elapsed = time.monotonic() - t0
        tb = traceback.format_exc()
        log(f"ERROR FATAL tras {elapsed:.1f}s:")
        for line in tb.splitlines():
            log(f"  {line}")
        error_result = {
            "error": tb,
            "files": [], "deleted": [],
            "total_files": 0, "total_deleted": 0,
            "image_info": {}, "strings": {}, "backend": "error"
        }
        try:
            with open(result_path, "w", encoding="utf-8") as f:
                json.dump(error_result, f, ensure_ascii=False)
        except Exception as e2:
            log(f"No se pudo escribir resultado de error: {e2}")
        log("Saliendo con código 1.")
        sys.exit(1)

if __name__ == "__main__":
    main()
