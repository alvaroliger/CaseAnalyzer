"""
analyzer.py — Motor forense cross-platform para CaseAnalyzer v4.0
Artefactos: filesystem, strings, hashes, OS, usuarios, browser history,
            LNK/Prefetch, ficheros sospechosos, clasificación por tipo.
"""

import os
import re
import sys
import struct
import subprocess
import platform
import shutil
import hashlib
import math
import tempfile
from pathlib import Path

# ─── Plataforma ───────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MACOS   = platform.system() == "Darwin"


def _find_7zip() -> str | None:
    for path in [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]:
        if Path(path).exists():
            return path
    return shutil.which("7z") or shutil.which("7za")


def _has_pytsk3() -> bool:
    try:
        import pytsk3  # noqa
        return True
    except ImportError:
        return False


def _find_tsk_binary(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    if IS_WINDOWS:
        for c in [
            rf"C:\Program Files\SleuthKit\bin\{name}.exe",
            rf"C:\Program Files\TSK\{name}.exe",
            rf"C:\tsk\{name}.exe",
        ]:
            if Path(c).exists():
                return c
    return None


def _get_wsl_exe() -> str | None:
    found = shutil.which("wsl")
    if found:
        return found
    wsl_abs = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "wsl.exe"
    return str(wsl_abs) if wsl_abs.exists() else None


def _has_wsl() -> bool:
    return _get_wsl_exe() is not None


def _wsl_has_sleuthkit(wsl_exe: str) -> bool:
    """Verifica que fls esté instalado DENTRO de WSL y tiene soporte EWF."""
    try:
        r = subprocess.run([wsl_exe, "which", "fls"], capture_output=True,
                           encoding="utf-8", errors="replace", timeout=30)
        if r.returncode != 0:
            print(
                "[analyzer] WSL disponible pero 'fls' no encontrado en WSL.\n"
                "  Instala sleuthkit dentro de WSL:\n"
                "    sudo apt update && sudo apt install -y sleuthkit ewf-tools",
                file=sys.stderr, flush=True,
            )
            return False
        # Verificar soporte EWF: fls debería aceptar .e01 directamente
        ewf_check = subprocess.run(
            [wsl_exe, "fls", "--help"], capture_output=True,
            encoding="utf-8", errors="replace", timeout=30
        )
        out = ((ewf_check.stdout or "") + (ewf_check.stderr or "")).lower()
        has_ewf = "ewf" in out or "e01" in out
        print(f"[analyzer] sleuthkit en WSL OK | soporte EWF nativo={'sí' if has_ewf else 'no'}",
              file=sys.stderr, flush=True)
        return True
    except Exception as e:
        print(f"[analyzer] WSL check fallo: {e}", file=sys.stderr, flush=True)
        return False


def _wsl_has_ewftools(wsl_exe: str) -> bool:
    """Verifica que ewfmount (ewf-tools) esté disponible en WSL."""
    try:
        r = subprocess.run([wsl_exe, "which", "ewfmount"], capture_output=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


_WSL_EXE      = _get_wsl_exe() or "wsl"
HAS_PYTSK3    = _has_pytsk3()
HAS_TSK_FLS   = _find_tsk_binary("fls") is not None
_WSL_OK       = _has_wsl() and _wsl_has_sleuthkit(_WSL_EXE)
HAS_WSL       = _WSL_OK
_WSL_HAS_EWF  = HAS_WSL and _wsl_has_ewftools(_WSL_EXE)
HAS_7ZIP      = _find_7zip() is not None
BACKEND       = ("pytsk3" if HAS_PYTSK3 else
                 "tsk"    if HAS_TSK_FLS else
                 "wsl"    if HAS_WSL else
                 "7zip"   if HAS_7ZIP else "none")


# ─── Subprocess helpers ───────────────────────────────────────────────────────
def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {timeout}s"
    except FileNotFoundError:
        return f"[NOT FOUND] {cmd[0]}"
    except Exception as e:
        return f"[ERROR] {e}"


def _run_binary(cmd: list[str], timeout: int = 30) -> bytes:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return r.stdout or b""
    except Exception:
        return b""


def _to_wsl_path(win_path: str) -> str:
    p = Path(win_path)
    drive = p.drive.replace(":", "").lower()
    rest  = str(p.relative_to(p.anchor)).replace("\\", "/")
    return f"/mnt/{drive}/{rest}"


def _shell_quote(s: str) -> str:
    """Escapa un argumento para uso en bash -c."""
    return "'" + s.replace("'", "'\\''") + "'"


def _tsk_cmd(base: list[str], image_path: str, offset: int | None = None,
             extra: list[str] | None = None, timeout_override: int | None = None,
             wsl_image_override: str | None = None,
             split_parts: list[str] | None = None) -> str:
    """Ejecuta un comando TSK local o via WSL.
    split_parts: lista de todas las partes de imagen split (para fls/icat)."""
    name       = base[0]
    use_split  = split_parts and len(split_parts) > 1
    if IS_WINDOWS and not _find_tsk_binary(name) and HAS_WSL:
        if use_split:
            wsl_paths = [_to_wsl_path(p) for p in split_parts]
        else:
            wsl_paths = [wsl_image_override or _to_wsl_path(image_path)]
        args = list(base[1:])
        if offset:
            args += ["-o", str(offset)]
        if extra:
            args += extra
        bash_cmd = " ".join([name] + [_shell_quote(a) for a in args]
                            + [_shell_quote(wp) for wp in wsl_paths])
        cmd = [_WSL_EXE, "bash", "-c", bash_cmd]
    else:
        bin_path = _find_tsk_binary(name) or name
        cmd = [bin_path] + list(base[1:])
        if offset:
            cmd += ["-o", str(offset)]
        if extra:
            cmd += extra
        if use_split:
            cmd += list(split_parts)
        else:
            cmd.append(image_path)
    return _run(cmd, timeout=timeout_override or 30)


def _wsl_ewf_full_analyze(image_path: str) -> dict:
    """Analiza un E01 completo en una única sesión bash WSL.
    ewfmount + fls + strings se ejecutan sin interrumpir el proceso FUSE."""
    wsl_src   = _to_wsl_path(image_path)
    mount_dir = f"/tmp/ca_ewf_{os.getpid()}"

    # Script bash que mantiene el mount FUSE vivo durante todo el análisis
    script = f"""#!/bin/bash
set -e
MOUNT_DIR={_shell_quote(mount_dir)}
WSL_SRC={_shell_quote(wsl_src)}

mkdir -p "$MOUNT_DIR"
ewfmount "$WSL_SRC" "$MOUNT_DIR" 2>/dev/null || {{ echo "[ewf] MOUNT_FAILED"; exit 1; }}
EWF1="$MOUNT_DIR/ewf1"

echo "===IMG_STAT==="
img_stat "$EWF1" 2>&1 || true

echo "===MMLS==="
mmls "$EWF1" 2>&1 || true

echo "===FSSTAT==="
OFF=$(mmls "$EWF1" 2>/dev/null \\
      | grep -iE 'ntfs|fat|ext[234]|linux|apple|hfs' \\
      | awk '{{print $3}}' | head -1)
if [ -n "$OFF" ]; then
    fsstat -o "$OFF" "$EWF1" 2>&1 || true
else
    fsstat "$EWF1" 2>&1 || true
fi

echo "===OFFSET==="
echo "$OFF"

echo "===FLS==="
if [ -n "$OFF" ]; then
    fls -r -m / -o "$OFF" "$EWF1" 2>&1 || true
else
    fls -r -m / "$EWF1" 2>&1 || true
fi

echo "===FLS_DEL==="
if [ -n "$OFF" ]; then
    fls -r -d -o "$OFF" "$EWF1" 2>&1 || true
else
    fls -r -d "$EWF1" 2>&1 || true
fi

echo "===STRINGS==="
# Montar el filesystem para extraer strings de ficheros reales (no bytes raw del dispositivo)
FS_MOUNT="/tmp/ca_ewf_fs_$$"
mkdir -p "$FS_MOUNT"
if [ -n "$OFF" ]; then
    mount -o loop,ro,offset=$(( OFF * 512 )) "$EWF1" "$FS_MOUNT" 2>/dev/null || true
else
    mount -o loop,ro "$EWF1" "$FS_MOUNT" 2>/dev/null || true
fi
if mountpoint -q "$FS_MOUNT" 2>/dev/null; then
    find "$FS_MOUNT" -type f -size -200M 2>/dev/null | while IFS= read -r f; do
        strings -n 8 "$f" 2>/dev/null | head -5000
        strings -e l -n 8 "$f" 2>/dev/null | head -2000
    done | head -200000
    umount "$FS_MOUNT" 2>/dev/null || true
else
    strings -n 8 "$EWF1" 2>/dev/null | head -100000 || true
    strings -e l -n 8 "$EWF1" 2>/dev/null | head -50000 || true
fi
rmdir "$FS_MOUNT" 2>/dev/null || true

ewfumount "$MOUNT_DIR" 2>/dev/null || true
rmdir "$MOUNT_DIR" 2>/dev/null || true
"""

    print(f"[ewf] iniciando análisis bash en {mount_dir}", file=sys.stderr, flush=True)
    try:
        r = _run_wsl_script(script, timeout=3600)
    except subprocess.TimeoutExpired:
        print("[ewf] timeout en análisis bash", file=sys.stderr, flush=True)
        return {}

    out = r.stdout
    if "[ewf] MOUNT_FAILED" in out or not out.strip():
        print(f"[ewf] ewfmount falló: {r.stderr[:300]}", file=sys.stderr, flush=True)
        return {}

    def _section(name: str) -> str:
        start = out.find(f"==={name}===")
        if start == -1:
            return ""
        start = out.index("\n", start) + 1
        end   = out.find("===", start)
        return out[start:end].strip() if end != -1 else out[start:].strip()

    img_stat   = _section("IMG_STAT")
    mmls_raw   = _section("MMLS")
    fsstat_raw = _section("FSSTAT")
    offset_str = _section("OFFSET").strip()
    fls_raw    = _section("FLS")
    fls_del    = _section("FLS_DEL")
    strings_raw = _section("STRINGS")

    try:
        offset = int(offset_str) if offset_str else None
    except ValueError:
        offset = None

    print(f"[ewf] offset={offset} fls_lines={len(fls_raw.splitlines())}",
          file=sys.stderr, flush=True)

    files   = _parse_fls(fls_raw)
    deleted = _parse_fls_del(fls_del)

    # Parsear strings del output bash
    strings_lines = strings_raw.splitlines()
    print(f"[ewf] strings extraídos: {len(strings_lines)}", file=sys.stderr, flush=True)
    cat: dict = {"urls": [], "emails": [], "paths": [], "ips": [], "other": []}
    for line in strings_lines[:_STRINGS_MAX_OUT]:
        line = line.strip()
        _classify_string(line, cat)

    return {
        "image_info": {
            "img_stat":   img_stat,
            "partitions": mmls_raw,
            "fsstat":     fsstat_raw,
        },
        "detected_offset": offset,
        "files":           files,
        "deleted":         deleted,
        "total_files":     len(files),
        "total_deleted":   len(deleted),
        "strings":         cat,
    }


# ─── Hashes ───────────────────────────────────────────────────────────────────
def _compute_hashes(image_path: str, split_parts: list[str] | None = None) -> dict:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    paths = split_parts if split_parts else [image_path]
    try:
        max_bytes  = 64 * 1024 * 1024
        read       = 0
        total_size = sum(os.path.getsize(p) for p in paths if os.path.exists(p))
        done       = False
        for path in paths:
            if done:
                break
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
                    read += len(chunk)
                    if read >= max_bytes:
                        done = True
                        break
        partial = read < total_size
        label   = f"(primeros {read // 1048576}MB de {total_size // 1048576}MB)" if partial else f"({total_size // 1048576}MB, completo)"
        sfx     = " *" if partial else ""
        return {"md5": md5.hexdigest() + sfx, "sha1": sha1.hexdigest() + sfx,
                "sha256": sha256.hexdigest() + sfx, "note": label}
    except Exception as e:
        return {"error": str(e)}


_EWF_SIGNATURES = (
    b"EVF\x09\x0d\x0a\xff\x00",  # EWF / E01 (EnCase, libewf)
    b"LVF\x09\x0d\x0a\xff\x00",  # Logical Evidence File
    b"EVF2\x0d\x0a\x81\x00",     # EWF2 / Ex01
)

_COMPRESSED_SIGNATURES = {
    b"\x37\x7a\xbc\xaf\x27\x1c": "7-Zip",
    b"\x50\x4b\x03\x04":         "ZIP",
    b"\x1f\x8b":                  "GZip",
    b"\x42\x5a\x68":              "BZip2",
    b"\xfd\x37\x7a\x58\x5a\x00": "XZ",
    b"\x52\x61\x72\x21\x1a\x07": "RAR",
}

def _detect_image_type(image_path: str) -> dict:
    try:
        with open(image_path, "rb") as f:
            header = f.read(512)
        for sig in _EWF_SIGNATURES:
            if header.startswith(sig):
                return {"type": "E01 (Expert Witness Format)", "mbr": False, "compressed": True}
        for sig, fmt in _COMPRESSED_SIGNATURES.items():
            if header.startswith(sig):
                extractable = fmt == "7-Zip"
                return {"type": f"Archivo comprimido ({fmt})", "mbr": False,
                        "compressed": True, "unsupported": True, "fmt": fmt,
                        "extractable": extractable,
                        "error": (
                            f"Este archivo es un {fmt} comprimido — extrayendo imagen interna..."
                            if extractable else
                            f"Este archivo es un {fmt} comprimido, no una imagen de disco. "
                            f"Extráelo primero para obtener la imagen .dd/.raw/.img y súbela."
                        )}
        if header.startswith(b"VMDK"):
            return {"type": "VMDK (VMware)", "mbr": False, "compressed": False}
        if header[:4] in (b"KDMV", b"COWD"):
            return {"type": "VMDK (VMware sparse)", "mbr": False, "compressed": False}
        if header[:8] == b"conectix":
            return {"type": "VHD (Microsoft)", "mbr": False, "compressed": False}
        if header[:4] == b"vhxf":
            return {"type": "VHDX (Microsoft)", "mbr": False, "compressed": False}
        if len(header) >= 512 and header[510:512] == b"\x55\xaa":
            return {"type": "Raw image (MBR)", "mbr": True, "compressed": False}
        return {"type": "Raw image", "mbr": False, "compressed": False}
    except Exception as e:
        return {"type": f"Error: {e}", "mbr": False, "compressed": False}


_IMAGE_DISK_EXTS = {'.dd', '.img', '.raw', '.iso', '.e01', '.vmdk', '.vhd', '.vhdx', '.bin'}
_SPLIT_EXT_RE    = re.compile(r'^\.\d{3}$')


def _gather_split_parts(image_path: str) -> list[str]:
    """Dado un .001, devuelve todas las partes (.001, .002, .003…) ordenadas.
    Si no es imagen split o solo hay una parte, devuelve [image_path]."""
    p = Path(image_path)
    if not _SPLIT_EXT_RE.match(p.suffix.lower()):
        return [image_path]
    try:
        parts = sorted(
            str(f) for f in p.parent.iterdir()
            if f.stem == p.stem and _SPLIT_EXT_RE.match(f.suffix.lower())
        )
    except Exception:
        return [image_path]
    return parts if len(parts) > 1 else [image_path]


def _extract_image_from_archive(archive_path: str, log_cb=None) -> "tuple[str | None, str | None]":
    """Extrae un archivo 7-Zip y devuelve (ruta_imagen_extraída, tmpdir).
    El llamador es responsable de borrar tmpdir con shutil.rmtree.
    Devuelve (None, None) si falla."""
    z = _find_7zip()
    if not z:
        if log_cb:
            log_cb("[extract] 7-Zip no está instalado — no se puede extraer automáticamente")
        return None, None

    def _p(msg):
        print(msg, file=sys.stderr, flush=True)
        if log_cb:
            log_cb(msg)

    tmpdir = tempfile.mkdtemp(prefix="ca_extract_")
    _p(f"[extract] Extrayendo {Path(archive_path).name} → {tmpdir} ...")
    try:
        r = subprocess.run(
            [z, "x", archive_path, f"-o{tmpdir}", "-y", "--"],
            timeout=3600, capture_output=True,
        )
    except subprocess.TimeoutExpired:
        _p("[extract] Timeout (>10 min) extrayendo archivo")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None, None
    except Exception as exc:
        _p(f"[extract] Error lanzando 7-Zip: {exc}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None, None

    if r.returncode not in (0, 1):
        snippet = (r.stderr or b"").decode(errors="replace")[:300]
        _p(f"[extract] 7-Zip rc={r.returncode}: {snippet}")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None, None

    all_files = [f for f in Path(tmpdir).rglob("*") if f.is_file()]
    if not all_files:
        _p("[extract] La extracción no produjo ficheros — ¿faltan volúmenes del archivo multiparte?")
        shutil.rmtree(tmpdir, ignore_errors=True)
        return None, None

    # Preferir ficheros con extensión de imagen conocida (más grande primero);
    # si no hay ninguno, tomar el fichero más grande
    candidates = sorted(
        [f for f in all_files if f.suffix.lower() in _IMAGE_DISK_EXTS],
        key=lambda f: f.stat().st_size, reverse=True
    )
    img = candidates[0] if candidates else max(all_files, key=lambda f: f.stat().st_size)
    _p(f"[extract] Imagen encontrada: {img.name} ({img.stat().st_size / 1_048_576:.1f} MB)")
    return str(img), tmpdir


def _estimate_entropy(image_path: str, sample: int = 1024 * 1024,
                      split_parts: list[str] | None = None) -> float:
    try:
        paths = split_parts if split_parts else [image_path]
        data = b""
        remaining = sample
        for path in paths:
            if remaining <= 0:
                break
            with open(path, "rb") as f:
                chunk = f.read(remaining)
            data += chunk
            remaining -= len(chunk)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        return round(-sum((c / n) * math.log2(c / n) for c in freq if c > 0), 4)
    except Exception:
        return 0.0


# ─── Lectura de contenido de fichero ─────────────────────────────────────────
def _read_file_bytes(image_path: str, inode: int, size: int,
                     img_offset: int = 0, max_bytes: int = 10 * 1024 * 1024,
                     split_parts: list[str] | None = None) -> bytes | None:
    """Extrae bytes de un fichero por inode. Usa pytsk3 o icat vía WSL."""
    to_read = min(size, max_bytes)
    if to_read <= 0:
        return None

    if HAS_PYTSK3:
        try:
            import pytsk3
            img_url = (",".join(split_parts)
                       if split_parts and len(split_parts) > 1 else image_path)
            img = pytsk3.Img_Info(img_url)
            fs  = pytsk3.FS_Info(img, offset=img_offset * 512)
            f   = fs.open_meta(inode=inode)
            return f.read_random(0, to_read)
        except Exception:
            return None

    if HAS_WSL or HAS_TSK_FLS:
        try:
            if IS_WINDOWS and not _find_tsk_binary("icat") and HAS_WSL:
                wsl_paths = ([_to_wsl_path(p) for p in split_parts]
                             if split_parts and len(split_parts) > 1
                             else [_to_wsl_path(image_path)])
                cmd = [_WSL_EXE, "icat", "-o", str(img_offset or 0)] + wsl_paths + [str(inode)]
            else:
                paths = split_parts if split_parts and len(split_parts) > 1 else [image_path]
                cmd = ([_find_tsk_binary("icat") or "icat", "-o", str(img_offset or 0)]
                       + paths + [str(inode)])
            data = _run_binary(cmd, timeout=30)
            return data[:to_read] if data else None
        except Exception:
            return None

    return None


# ─── pytsk3 backend ───────────────────────────────────────────────────────────
def _pytsk3_analyze(image_path: str, split_parts: list[str] | None = None) -> dict:
    import pytsk3

    result = {
        "backend": "pytsk3", "files": [], "deleted": [],
        "image_info": {}, "strings": {},
    }

    # Imagen split: pytsk3/TSK acepta rutas separadas por coma
    img_url = ",".join(split_parts) if split_parts and len(split_parts) > 1 else image_path
    if split_parts and len(split_parts) > 1:
        print(f"[pytsk3] imagen split: {len(split_parts)} partes → {img_url[:120]}",
              file=sys.stderr, flush=True)

    try:
        try:
            img = pytsk3.Img_Info(img_url)
            img.get_size()
        except Exception:
            img = pytsk3.Img_Info(url=img_url, type=pytsk3.TSK_IMG_TYPE_EWF_EWF)

        size = img.get_size()
        result["image_info"]["img_stat"] = (
            f"Imagen abierta con pytsk3\n"
            f"Tamaño: {size:,} bytes  ({size / 1073741824:.2f} GB)\n"
            f"Plataforma: {platform.system()} {platform.release()}"
        )

        offset = None
        try:
            vol = pytsk3.Volume_Info(img)
            rows = ["Slot  Start       Length      Descripción", "-" * 52]
            for part in vol:
                desc = part.desc.decode(errors="replace")
                rows.append(f"  {part.addr:3d}  {part.start:10d}  {part.len:10d}  {desc}")
                if offset is None:
                    if any(k in desc.lower() for k in ["linux", "ntfs", "fat", "ext", "apple"]):
                        offset = part.start
            result["image_info"]["partitions"] = "\n".join(rows)
            result["detected_offset"] = offset
        except Exception:
            result["image_info"]["partitions"] = "(sin tabla de particiones)"
            result["detected_offset"] = None

        try:
            off_bytes = (offset or 0) * 512
            fs = pytsk3.FS_Info(img, offset=off_bytes)
            result["image_info"]["fsstat"] = (
                f"Filesystem : {fs.info.ftype}\n"
                f"Bloques    : {fs.info.block_count:,}  ({fs.info.block_size} bytes/bloque)\n"
                f"Inodes     : {fs.info.inum_count:,}  (primero: {fs.info.first_inum})\n"
                f"Offset     : {offset or 0} sectores"
            )

            def walk(directory, prefix="", depth=0):
                if depth > 20:
                    return
                for entry in directory:
                    try:
                        name = entry.info.name.name.decode(errors="replace")
                        if name in (".", ".."):
                            continue
                        meta    = entry.info.meta
                        is_dir  = meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR
                        deleted = bool(meta and meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
                        inode   = meta.addr if meta else None
                        fe = {
                            "name": prefix + name,
                            "type": "dir" if is_dir else "file",
                            "deleted": deleted,
                            "size": str(meta.size if meta else 0),
                            "inode": str(inode) if inode is not None else "—",
                            "mtime": str(meta.mtime) if meta and meta.mtime else "—",
                            "atime": str(meta.atime) if meta and meta.atime else "—",
                            "ctime": str(meta.ctime) if meta and meta.ctime else "—",
                        }
                        result["files"].append(fe)
                        if deleted:
                            result["deleted"].append({"raw": prefix + name,
                                                       "name": prefix + name,
                                                       "inode": str(inode) if inode else "—"})
                        if is_dir and not deleted and inode:
                            try:
                                walk(fs.open_dir(inode=inode), prefix + name + "/", depth + 1)
                            except Exception:
                                pass
                    except Exception:
                        continue

            walk(fs.open_dir(path="/"))
        except Exception as e:
            result["image_info"]["fsstat"] = f"No se pudo abrir filesystem: {e}"

    except Exception as e:
        print(f"[pytsk3] Error abriendo imagen: {e}", file=sys.stderr, flush=True)
        result["image_info"]["img_stat"] = f"Error al abrir con pytsk3: {e}"

    result["total_files"]   = len(result["files"])
    result["total_deleted"] = len(result["deleted"])
    result["strings"]       = _extract_strings(image_path, split_parts=split_parts)
    return result


# ─── TSK/WSL backend ─────────────────────────────────────────────────────────
def _extract_strings_wsl(wsl_path: str) -> dict:
    """Extrae strings desde una ruta WSL (e.g. imagen raw montada via ewfmount)."""
    cat: dict = {"urls": [], "emails": [], "paths": [], "ips": [], "other": []}
    try:
        raw = _run([_WSL_EXE, "bash", "-c",
                    f"{{ strings -n 8 {_shell_quote(wsl_path)}; strings -e l -n 8 {_shell_quote(wsl_path)}; }} 2>/dev/null"],
                   timeout=600)
        lines = raw.splitlines()
        print(f"[strings-wsl] {len(lines)} strings extraídos de {wsl_path}",
              file=sys.stderr, flush=True)
        for line in lines[:_STRINGS_MAX_OUT]:
            line = line.strip()
            _classify_string(line, cat)
    except Exception as e:
        cat["_error"] = str(e)
    return cat


def _is_ewf_image(image_path: str) -> bool:
    try:
        with open(image_path, "rb") as f:
            h = f.read(8)
        return any(h.startswith(sig[:8]) for sig in _EWF_SIGNATURES)
    except Exception:
        return False


def _wsl_detect_fs(wsl_path: str) -> str:
    """Detecta el tipo de filesystem de una imagen via WSL file(1)."""
    try:
        r = subprocess.run([_WSL_EXE, "bash", "-c", f"file {_shell_quote(wsl_path)} 2>/dev/null"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=10)
        out = r.stdout.lower()
        if "udf"      in out: return "udf"
        if "iso 9660" in out: return "iso9660"
        if "ntfs"     in out: return "ntfs"
        if "fat"      in out: return "fat"
        if "ext2"     in out or "ext3" in out or "ext4" in out: return "ext"
        if "btrfs"    in out: return "btrfs"
    except Exception:
        pass
    return "unknown"


def _run_wsl_script(script: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """Escribe un script bash a un fichero temporal y lo ejecuta como root en WSL.
    Evita el problema de codificación de comillas al pasar scripts via -c en Windows."""
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".sh", delete=False, encoding="utf-8", newline="\n"
    ) as tf:
        tf.write(script)
        win_path = tf.name
    wsl_script = _to_wsl_path(win_path)
    try:
        return subprocess.run(
            [_WSL_EXE, "-u", "root", "bash", wsl_script],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout,
        )
    finally:
        try:
            os.unlink(win_path)
        except Exception:
            pass


def _wsl_mount_analyze(image_path: str, fs_type: str = "") -> dict:
    """Analiza una imagen montándola via WSL (UDF, ISO9660, etc.)
    Todo ocurre en una única sesión bash para que el mount persista."""
    wsl_src   = _to_wsl_path(image_path)
    mount_dir = f"/tmp/ca_mnt_{os.getpid()}"
    fs_opt    = f"-t {fs_type}" if fs_type and fs_type != "unknown" else ""

    script = f"""#!/bin/bash
MOUNT={_shell_quote(mount_dir)}
SRC={_shell_quote(wsl_src)}

mkdir -p "$MOUNT"
mount {fs_opt} -o loop,ro "$SRC" "$MOUNT" 2>/dev/null || \
mount -o loop,ro "$SRC" "$MOUNT" 2>/dev/null || {{ echo "[mount] MOUNT_FAILED" >&2; exit 1; }}
echo "[mount] montado OK en $MOUNT" >&2

echo "===FSINFO==="
df -h "$MOUNT" 2>/dev/null || true
echo "Filesystem: {fs_type}"

echo "===FILES==="
find "$MOUNT" -ls 2>/dev/null

echo "===STRINGS==="
find "$MOUNT" -type f -size -200M 2>/dev/null | while IFS= read -r f; do
    strings -n 8 "$f" 2>/dev/null | sed 's|^|['"$f"'] |' | head -5000
done | head -200000

umount "$MOUNT" 2>/dev/null || true
rmdir "$MOUNT" 2>/dev/null || true
"""

    print(f"[mount] analizando via WSL root mount ({fs_type}): {wsl_src}", file=sys.stderr, flush=True)
    try:
        r = _run_wsl_script(script, timeout=3600)
    except subprocess.TimeoutExpired:
        print("[mount] timeout", file=sys.stderr, flush=True)
        return {}

    out = r.stdout
    err = r.stderr
    for line in err.splitlines():
        print(f"[mount-wsl] {line}", file=sys.stderr, flush=True)

    if "MOUNT_FAILED" in err or not out.strip():
        return {}

    def _section(name: str) -> str:
        start = out.find(f"==={name}===")
        if start == -1:
            return ""
        start = out.index("\n", start) + 1
        end   = out.find("===", start)
        return out[start:end].strip() if end != -1 else out[start:].strip()

    fsinfo_raw   = _section("FSINFO")
    files_raw    = _section("FILES")
    strings_raw  = _section("STRINGS")

    # Parsear listado find -ls: campos: inode links perms size user group size mtime name
    files: list[dict] = []
    deleted: list[dict] = []
    for line in files_raw.splitlines():
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        perms    = parts[2]
        size     = parts[6]
        mtime    = " ".join(parts[7:10])
        fullpath = parts[10].strip()
        rel      = fullpath.replace(mount_dir, "")
        is_dir   = perms.startswith("d")
        files.append({
            "name":    rel or "/",
            "type":    "dir" if is_dir else "file",
            "size":    size,
            "mtime":   mtime,
            "atime":   "—",
            "ctime":   "—",
            "inode":   parts[0],
            "deleted": False,
        })

    print(f"[mount] {len(files)} entradas encontradas", file=sys.stderr, flush=True)

    # Parsear strings con contexto de fichero
    strings_cat: dict = {"urls": [], "emails": [], "paths": [], "ips": [], "other": []}
    for raw_line in strings_raw.splitlines()[:_STRINGS_MAX_OUT]:
        # formato: [/tmp/ca_mnt_xxx/ruta/archivo] string
        if raw_line.startswith("[") and "] " in raw_line:
            line = raw_line.split("] ", 1)[1].strip()
        else:
            line = raw_line.strip()
        _classify_string(line, strings_cat)

    for k in strings_cat:
        strings_cat[k] = list(dict.fromkeys(strings_cat[k]))

    return {
        "image_info": {
            "img_stat":   fsinfo_raw,
            "partitions": f"Filesystem: {fs_type}\nMontado via loop device en WSL",
            "fsstat":     fsinfo_raw,
        },
        "detected_offset": None,
        "files":           files,
        "deleted":         deleted,
        "total_files":     len(files),
        "total_deleted":   0,
        "strings":         strings_cat,
    }


def _pycdlib_analyze(image_path: str) -> dict:
    """Analiza imágenes ISO9660/UDF/Joliet usando pycdlib (puro Python, sin dependencias externas)."""
    try:
        import pycdlib
    except ImportError:
        print("[pycdlib] no instalado", file=sys.stderr, flush=True)
        return {}

    print(f"[pycdlib] abriendo {image_path}", file=sys.stderr, flush=True)
    iso = pycdlib.PyCdlib()
    try:
        iso.open(image_path)
    except Exception as e:
        print(f"[pycdlib] error abriendo imagen: {e}", file=sys.stderr, flush=True)
        return {}

    # Elegir la facade con más soporte: UDF > Joliet > ISO9660
    has_udf    = iso.has_udf()
    has_joliet = iso.has_joliet()
    facade_name = "UDF" if has_udf else ("Joliet" if has_joliet else "ISO9660")
    print(f"[pycdlib] tipo detectado: {facade_name}", file=sys.stderr, flush=True)

    if has_udf:
        facade = iso.get_udf_facade()
        list_children = lambda path: facade.list_children(udf_path=path)
        get_record    = lambda path: facade.get_record(udf_path=path)
        join_path     = lambda parent, name: (parent.rstrip("/") + "/" + name)
        root_path     = "/"
    elif has_joliet:
        facade = iso.get_joliet_facade()
        list_children = lambda path: facade.list_children(joliet_path=path)
        get_record    = lambda path: facade.get_record(joliet_path=path)
        join_path     = lambda parent, name: (parent.rstrip("/") + "/" + name)
        root_path     = "/"
    else:
        list_children = lambda path: iso.list_children(iso_path=path)
        get_record    = lambda path: iso.get_record(iso_path=path)
        join_path     = lambda parent, name: (parent.rstrip("/") + "/" + name)
        root_path     = "/"

    files: list[dict] = []
    strings_cat: dict = {"urls": [], "emails": [], "paths": [], "ips": [], "other": []}
    total_str   = 0
    MAX_FILES   = 10_000
    MAX_STR     = _STRINGS_MAX_OUT * 3

    def _walk(dir_path: str, depth: int = 0):
        nonlocal total_str
        if depth > 25 or len(files) >= MAX_FILES:
            return
        try:
            children = list(list_children(dir_path))
        except Exception:
            return
        for child in children:
            try:
                if has_udf:
                    name = child.file_identifier.decode(errors="replace") if isinstance(child.file_identifier, bytes) else str(child.file_identifier)
                    is_dir = child.icb_tag.file_type == 4  # UDF dir
                    fsize  = child.info_length if hasattr(child, "info_length") else 0
                else:
                    name = child.file_identifier.decode(errors="replace") if isinstance(child.file_identifier, bytes) else str(child.file_identifier)
                    is_dir = child.is_dir()
                    fsize  = child.get_data_length() if not is_dir else 0

                if name in (".", "\x00", "\x01", ""):
                    continue
                full_path = join_path(dir_path, name)
                files.append({
                    "name":    full_path,
                    "type":    "dir" if is_dir else "file",
                    "size":    str(fsize),
                    "mtime":   "",
                    "atime":   "",
                    "ctime":   "",
                    "inode":   "—",
                    "deleted": False,
                })
                if is_dir:
                    _walk(full_path, depth + 1)
                elif fsize > 0 and fsize < 50 * 1024 * 1024 and total_str < MAX_STR:
                    # Extraer contenido para strings
                    try:
                        buf = bytearray()
                        if has_udf:
                            facade.get_file_from_iso(fileobj=_ByteWriter(buf), udf_path=full_path)
                        elif has_joliet:
                            facade.get_file_from_iso(fileobj=_ByteWriter(buf), joliet_path=full_path)
                        else:
                            iso.get_file_from_iso(fileobj=_ByteWriter(buf), iso_path=full_path)
                        data = bytes(buf)
                        for m in _ASCII_PAT.finditer(data):
                            if total_str >= MAX_STR:
                                break
                            _classify_string(m.group().decode("ascii", errors="replace").strip(), strings_cat)
                            total_str += 1
                        for m in _UTF16LE_PAT.finditer(data):
                            if total_str >= MAX_STR:
                                break
                            s = _decode_utf16le(m.group())
                            if s and len(s) >= 8:
                                _classify_string(s, strings_cat)
                                total_str += 1
                    except Exception:
                        pass
            except Exception:
                continue

    _walk(root_path)
    iso.close()

    for k in strings_cat:
        strings_cat[k] = list(dict.fromkeys(strings_cat[k]))[:_STRINGS_MAX_OUT]

    total_s = sum(len(strings_cat[k]) for k in ("urls", "emails", "paths", "ips", "other"))
    print(f"[pycdlib] {len(files)} ficheros | strings: {total_s} "
          f"(urls={len(strings_cat['urls'])} ips={len(strings_cat['ips'])} "
          f"other={len(strings_cat['other'])})",
          file=sys.stderr, flush=True)

    return {
        "image_info": {
            "img_stat":   f"Analizado con pycdlib\nFormato: {facade_name}\nFicheros: {len(files)}",
            "partitions": f"Filesystem: {facade_name} (ISO/UDF)",
            "fsstat":     f"Tipo: {facade_name} | Entradas: {len(files)}",
        },
        "detected_offset": None,
        "files":           files,
        "deleted":         [],
        "total_files":     len(files),
        "total_deleted":   0,
        "strings":         strings_cat,
    }


class _ByteWriter:
    """File-like object para pycdlib.get_file_from_iso."""
    def __init__(self, buf: bytearray):
        self._buf = buf

    def write(self, data: bytes) -> int:
        self._buf.extend(data)
        return len(data)


def _7zip_analyze(image_path: str) -> dict:
    """Analiza una imagen usando 7-Zip (soporta UDF, ISO9660, FAT, NTFS, etc.).
    No necesita WSL ni sudo. Extrae ficheros a un directorio temporal para análisis."""
    z = _find_7zip()
    if not z:
        print("[7z] 7-Zip no encontrado en el sistema", file=sys.stderr, flush=True)
        return {}

    print(f"[7z] listando contenido de {image_path}", file=sys.stderr, flush=True)
    try:
        r = subprocess.run(
            [z, "l", "-slt", "--", image_path],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=300,
        )
    except subprocess.TimeoutExpired:
        print("[7z] timeout en listado", file=sys.stderr, flush=True)
        return {}
    except Exception as e:
        print(f"[7z] error en listado: {e}", file=sys.stderr, flush=True)
        return {}

    if r.returncode not in (0, 1):
        print(f"[7z] listado falló rc={r.returncode}: {r.stderr[:200]}", file=sys.stderr, flush=True)
        return {}

    # Parsear salida -slt: bloques por fichero separados por línea vacía
    parsed_files: list[dict] = []
    current: dict = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            if current.get("Path"):
                parsed_files.append(current)
            current = {}
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            current[key.strip()] = val.strip()
    if current.get("Path"):
        parsed_files.append(current)

    files: list[dict] = []
    for f in parsed_files:
        attr = f.get("Attributes", "")
        is_dir = attr.startswith("D") or attr.startswith("d")
        files.append({
            "name":    f.get("Path", ""),
            "type":    "dir" if is_dir else "file",
            "size":    f.get("Size", "0"),
            "mtime":   f.get("Modified", ""),
            "atime":   f.get("Accessed", ""),
            "ctime":   f.get("Created", ""),
            "inode":   "—",
            "deleted": False,
        })

    print(f"[7z] {len(files)} entradas encontradas", file=sys.stderr, flush=True)

    # Extraer ficheros a temporal para extracción de strings de calidad
    strings_cat: dict = {"urls": [], "emails": [], "paths": [], "ips": [], "other": []}
    total_str = 0
    try:
        with tempfile.TemporaryDirectory(prefix="ca7z_") as tmpdir:
            print(f"[7z] extrayendo a {tmpdir}...", file=sys.stderr, flush=True)
            subprocess.run(
                [z, "e", image_path, f"-o{tmpdir}", "-y", "-bso0", "-bse0", "--"],
                timeout=3600, capture_output=True
            )
            for root, _, filenames in os.walk(tmpdir):
                for fname in filenames:
                    fpath = os.path.join(root, fname)
                    try:
                        fsize = os.path.getsize(fpath)
                        if fsize > 200 * 1024 * 1024:
                            continue
                        with open(fpath, "rb") as fh:
                            data = fh.read()
                        for m in _ASCII_PAT.finditer(data):
                            if total_str >= _STRINGS_MAX_OUT * 3:
                                break
                            _classify_string(m.group().decode("ascii", errors="replace").strip(), strings_cat)
                            total_str += 1
                        for m in _UTF16LE_PAT.finditer(data):
                            if total_str >= _STRINGS_MAX_OUT * 3:
                                break
                            s = _decode_utf16le(m.group())
                            if s and len(s) >= 8:
                                _classify_string(s, strings_cat)
                                total_str += 1
                    except Exception:
                        continue
    except Exception as e:
        print(f"[7z] error en extracción de strings: {e}", file=sys.stderr, flush=True)

    for k in strings_cat:
        strings_cat[k] = list(dict.fromkeys(strings_cat[k]))[:_STRINGS_MAX_OUT]

    total = sum(len(strings_cat[k]) for k in ("urls", "emails", "paths", "ips", "other"))
    print(f"[7z] strings: {total} únicos "
          f"(urls={len(strings_cat['urls'])} emails={len(strings_cat['emails'])} "
          f"ips={len(strings_cat['ips'])} paths={len(strings_cat['paths'])} "
          f"other={len(strings_cat['other'])})",
          file=sys.stderr, flush=True)

    # Detectar tipo de filesystem desde 7z output
    fs_type_line = ""
    for line in r.stdout.splitlines()[:30]:
        if line.strip().startswith("Type ="):
            fs_type_line = line.strip()
            break

    return {
        "image_info": {
            "img_stat":   f"Analizado con 7-Zip v{_7zip_version(z)}\n{fs_type_line}\nFicheros: {len(files)}",
            "partitions": "Listado directo vía 7-Zip (sin tabla de particiones MBR/GPT)",
            "fsstat":     fs_type_line or "Sin información de filesystem",
        },
        "detected_offset": None,
        "files":           files,
        "deleted":         [],
        "total_files":     len(files),
        "total_deleted":   0,
        "strings":         strings_cat,
    }


def _7zip_version(z: str) -> str:
    try:
        r = subprocess.run([z], capture_output=True, text=True, timeout=5, errors="replace")
        m = re.search(r'7-Zip\s+[\w.]+\s+([\d.]+)', r.stdout + r.stderr)
        return m.group(1) if m else "?"
    except Exception:
        return "?"


def _tsk_analyze(image_path: str, split_parts: list[str] | None = None) -> dict:

    result = {
        "backend": "tsk_binaries" if HAS_TSK_FLS else "wsl",
        "image_info": {}, "files": [], "deleted": [], "strings": {},
    }
    if split_parts and len(split_parts) > 1:
        print(f"[tsk] imagen split: {len(split_parts)} partes", file=sys.stderr, flush=True)

    is_ewf = _is_ewf_image(image_path)

    # E01 + WSL: todo en una única sesión bash para que el mount FUSE no muera
    if is_ewf and HAS_WSL and not HAS_TSK_FLS and _WSL_HAS_EWF:
        ewf_data = _wsl_ewf_full_analyze(image_path)
        if ewf_data:
            result.update(ewf_data)
            result["backend"] = "wsl"
            return result

    # Detectar filesystem via WSL file(1) para elegir backend adecuado
    if HAS_WSL and not HAS_TSK_FLS:
        wsl_src = _to_wsl_path(image_path)
        fs_type = _wsl_detect_fs(wsl_src)
        print(f"[tsk] filesystem detectado: {fs_type}", file=sys.stderr, flush=True)

        # UDF / ISO9660: TSK no soporta — intentar pycdlib (Python puro), luego WSL mount, luego 7-Zip
        if fs_type in ("udf", "iso9660", "btrfs"):
            # 1. pycdlib — sin dependencias externas, funciona en Windows directamente
            pycd_data = _pycdlib_analyze(image_path)
            if pycd_data and pycd_data.get("total_files", 0) > 1:
                result.update(pycd_data)
                result["backend"] = f"pycdlib_{fs_type}"
                return result
            # 2. WSL mount
            mount_data = _wsl_mount_analyze(image_path, fs_type)
            if mount_data and mount_data.get("total_files", 0) > 1:
                result.update(mount_data)
                result["backend"] = f"wsl_mount_{fs_type}"
                return result
            # 3. 7-Zip
            print(f"[tsk] pycdlib y WSL mount fallaron para {fs_type}, intentando 7-Zip",
                  file=sys.stderr, flush=True)
            z_data = _7zip_analyze(image_path)
            if z_data and z_data.get("total_files", 0) > 1:
                result.update(z_data)
                result["backend"] = f"7zip_{fs_type}"
                return result

    # NTFS/FAT/EXT: TSK via WSL bash -c
    result["image_info"]["img_stat"] = _tsk_cmd(["img_stat"], image_path)
    mmls_raw = _tsk_cmd(["mmls"], image_path)
    result["image_info"]["partitions"] = mmls_raw
    offset = _parse_offset(mmls_raw)
    result["detected_offset"] = offset

    print(f"[tsk] mmls offset={offset}", file=sys.stderr, flush=True)

    result["image_info"]["fsstat"] = _tsk_cmd(["fsstat"], image_path, offset)

    fls_raw = _tsk_cmd(["fls", "-r", "-m", "/"], image_path, offset,
                        timeout_override=600, split_parts=split_parts)
    files = _parse_fls(fls_raw)
    print(f"[tsk] fls offset={offset} → {len(files)} entradas", file=sys.stderr, flush=True)

    probe_offsets: list[int] = [s for s, _ in _mmls_partitions(mmls_raw)]
    for fb in [0, 63, 2048, 128, 2056]:
        if fb not in probe_offsets:
            probe_offsets.append(fb)

    best_files  = files
    best_offset = offset

    for try_offset in probe_offsets:
        if try_offset == (offset or 0):
            continue
        alt = _tsk_cmd(["fls", "-r", "-m", "/"], image_path, try_offset or None,
                        timeout_override=300, split_parts=split_parts)
        alt_files = _parse_fls(alt)
        print(f"[tsk] fls probe offset={try_offset} → {len(alt_files)} entradas",
              file=sys.stderr, flush=True)
        if len(alt_files) > len(best_files):
            best_files  = alt_files
            best_offset = try_offset or None

    if len(best_files) > len(files):
        files  = best_files
        offset = best_offset
        result["detected_offset"] = offset
        result["image_info"]["fsstat"] = _tsk_cmd(["fsstat"], image_path, offset,
                                                   split_parts=split_parts)

    if len(files) <= 1:
        print("[tsk] fls no encontró ficheros, intentando pycdlib...", file=sys.stderr, flush=True)
        pycd_data = _pycdlib_analyze(image_path)
        if pycd_data and pycd_data.get("total_files", 0) > 1:
            result.update(pycd_data)
            result["backend"] = "pycdlib_fallback"
            return result
        print("[tsk] pycdlib sin resultados, intentando 7-Zip...", file=sys.stderr, flush=True)
        z_data = _7zip_analyze(image_path)
        if z_data and z_data.get("total_files", 0) > 1:
            result.update(z_data)
            result["backend"] = "7zip_fallback"
            return result

    result["files"]         = files
    result["total_files"]   = len(files)

    del_raw = _tsk_cmd(["fls", "-r", "-d"], image_path, offset,
                       timeout_override=600, split_parts=split_parts)
    result["deleted"]       = _parse_fls_del(del_raw)
    result["total_deleted"] = len(result["deleted"])
    result["strings"]       = _extract_strings(image_path, split_parts=split_parts)
    return result


# ─── Strings ─────────────────────────────────────────────────────────────────
_STRINGS_SAMPLE_MB = 64      # MB por muestra (muestreamos 4 zonas del disco)
_STRINGS_MAX_OUT   = 25_000  # strings únicos máximos en salida
_STRINGS_HARD_SECS = 600     # deadline total (10 min) para imágenes grandes
_ASCII_PAT    = re.compile(rb'[ -~]{8,200}')
# UTF-16LE: pares (byte_ASCII, 0x00) — habitual en NTFS/Registro Windows
_UTF16LE_PAT  = re.compile(rb'(?:[ -~]\x00){6,150}')
# URL: sólo caracteres RFC-3986 válidos para evitar capturar basura binaria adyacente
_url_re    = re.compile(r"(?:https?|ftp|file)://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{5,500}")
_email_re  = re.compile(r'[\w.\-+]{2,}@[\w.\-]+\.\w{2,8}')
# Rutas reales: caracteres ASCII explícitos, sin \w Unicode.
# Windows: primer componente debe empezar con letra o $ (no dígito) para evitar
# secuencias binarias tipo C:\00000030a0000008
_path_re   = re.compile(
    r'(/[a-zA-Z][a-zA-Z0-9_./\- ]{4,120}'                         # /usr/bin/python
    r'|/[a-zA-Z0-9_\-]{2,40}/[a-zA-Z][a-zA-Z0-9_./\- ]{2,80}'    # /etc/passwd
    r'|[A-Za-z]:\\[$a-zA-Z_][a-zA-Z0-9 _.\\/\-~]{3,120})'         # C:\Windows\System32
)
_ip_re        = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
# Filtro secundario para rutas: exige ≥3 letras consecutivas (descarta hex/binario)
_PATH_REAL_RE = re.compile(r'[a-zA-Z]{3,}')
# Palabra real: ≥4 letras minúsculas con al menos 1 vocal → excluye 'mqgwj'
_word_re       = re.compile(r'[a-z]*[aeiou][a-z]{2,}|[a-z]{2,}[aeiou][a-z]*')
_known_frag_re = re.compile(
    r'(?:Windows|System|Program|Users|Desktop|Documents|Downloads|AppData|'
    r'Microsoft|Software|Registry|NTFS|FAT|Linux|Adobe|Office|Chrome|Firefox|'
    r'version|error|warning|failed|success|login|password|admin|user|root|'
    r'\.exe|\.dll|\.doc|\.pdf|\.jpg|\.png|\.zip|\.rar|'
    r'http|ftp|smtp|imap|pop3|ssh|rdp|vnc)',
    re.IGNORECASE
)
# Caracteres que indican datos binarios/aleatorios
_BAD_CHARS_RE  = re.compile(r'[^\x20-\x7e]|[{}\[\]<>|\\^~`]')


def _decode_utf16le(data: bytes) -> str:
    """Decodifica una secuencia UTF-16LE (ej. capturada por _UTF16LE_PAT) a str."""
    try:
        return data.decode('utf-16-le', errors='replace').rstrip('\x00')
    except Exception:
        return ''


def _classify_string(line: str, cat: dict) -> None:
    """Clasifica un string en la categoría forense correcta.
    Extrae SÓLO el grupo capturado por el regex, nunca el contexto circundante."""
    if not line:
        return
    m = _url_re.search(line)
    if m:
        cat["urls"].append(m.group()[:500])
        return
    m = _email_re.search(line)
    if m:
        cat["emails"].append(m.group()[:200])
        return
    m = _path_re.search(line)
    if m:
        path  = m.group()
        win   = len(path) > 2 and path[1:3] == ':\\'
        sep   = '\\' if win else '/'
        inner = path[3:] if win else path[1:]
        # Requiere ≥2 componentes (sep dentro del cuerpo) Y ≥3 letras seguidas
        # Filtra: /Thomson, /certs, /c2c5c9cA..., /r2r4r8rE...
        if sep in inner and _PATH_REAL_RE.search(inner):
            cat["paths"].append(path[:300])
        return
    m = _ip_re.search(line)
    if m:
        cat["ips"].append(m.group()[:50])
        return
    if _is_meaningful_string(line):
        cat["other"].append(line[:200])


def _is_meaningful_string(s: str) -> bool:
    """Descarta strings binarios/aleatorios que no aportan valor forense.
    Solo pasan strings que parecen texto humano o artefactos conocidos."""
    if len(s) < 8:
        return False
    # Patrón forense conocido: siempre aceptar
    if _known_frag_re.search(s):
        return True
    # Strings con caracteres binarios/de control: rechazar
    bad = len(_BAD_CHARS_RE.findall(s))
    if bad > 2 or (bad > 0 and len(s) < 20):
        return False
    alpha = sum(c.isalpha() for c in s)
    lower = sum(c.islower() for c in s)
    ratio = alpha / len(s)
    # Texto real: >65% alfabético + >35% minúsculas + palabra con vocal
    if ratio >= 0.65 and lower / len(s) >= 0.35:
        if _word_re.search(s):
            return True
    # Strings con espacio: más probable que sean texto legible
    if " " in s and ratio >= 0.55 and lower / len(s) >= 0.30 and _word_re.search(s):
        return True
    return False


def _is_compressed_container(image_path: str) -> bool:
    """Devuelve True si el fichero es un contenedor comprimido (E01, etc.)
    que no debe leerse en crudo para extracción de strings."""
    try:
        with open(image_path, "rb") as f:
            header = f.read(8)
        for sig in _EWF_SIGNATURES:
            if header.startswith(sig[:len(header)]):
                return True
    except Exception:
        pass
    return False


def _extract_strings(image_path: str, min_len: int = 8,
                     split_parts: list[str] | None = None) -> dict:
    import time
    t0   = time.monotonic()
    cat  = {"urls": [], "emails": [], "paths": [], "ips": [], "other": []}
    dl   = t0 + _STRINGS_HARD_SECS

    if _is_compressed_container(image_path):
        print("[strings] formato E01/EWF detectado — contenido comprimido, omitiendo extraccion directa",
              file=sys.stderr, flush=True)
        cat["_skipped"] = "E01/EWF: el contenido esta comprimido. Se requiere pytsk3 o ewftools para extraccion real."
        return cat

    paths = split_parts if split_parts else [image_path]
    print(f"[strings] iniciando extraccion (partes={len(paths)}, deadline={_STRINGS_HARD_SECS}s, IS_WINDOWS={IS_WINDOWS})",
          file=sys.stderr, flush=True)

    if IS_WINDOWS:
        lines = _extract_strings_python(image_path, dl, split_parts=paths)
    else:
        all_lines: list[str] = []
        for path in paths:
            if time.monotonic() > dl:
                break
            all_lines.extend(_run(["strings", f"-n{min_len}", path],
                                  timeout=_STRINGS_HARD_SECS - 2).splitlines())
        lines = all_lines

    print(f"[strings] {len(lines)} líneas brutas obtenidas en {time.monotonic()-t0:.2f}s",
          file=sys.stderr, flush=True)

    for line in lines[:_STRINGS_MAX_OUT]:
        if time.monotonic() > dl:
            cat["_truncated"] = True
            break
        line = line.strip()
        if not line or len(line) < min_len:
            continue
        _classify_string(line, cat)

    for k in ("urls", "emails", "paths", "ips", "other"):
        cat[k] = list(dict.fromkeys(cat[k]))

    total = sum(len(cat[k]) for k in ("urls", "emails", "paths", "ips", "other"))
    print(f"[strings] clasificación completa: {total} strings únicos "
          f"(urls={len(cat['urls'])} emails={len(cat['emails'])} "
          f"ips={len(cat['ips'])} paths={len(cat['paths'])} other={len(cat['other'])})"
          f" en {time.monotonic()-t0:.2f}s total",
          file=sys.stderr, flush=True)
    return cat


def _extract_strings_python(path: str, deadline: float,
                             split_parts: list[str] | None = None) -> list[str]:
    import time
    t0      = time.monotonic()
    results: list[str] = []
    sample  = _STRINGS_SAMPLE_MB * 1024 * 1024
    raw_cap = _STRINGS_MAX_OUT * 3
    paths   = split_parts if split_parts else [path]

    for part_idx, cur_path in enumerate(paths):
        if time.monotonic() > deadline or len(results) >= raw_cap:
            break
        try:
            file_size = os.path.getsize(cur_path)
            quarters  = [0, file_size // 4, file_size // 2, (file_size * 3) // 4]
            offsets   = [max(0, q - sample // 2) for q in quarters]
            seen_off: set[int] = set()
            offsets = [o for o in offsets if not (o in seen_off or seen_off.add(o))]
            print(f"[strings] parte {part_idx+1}/{len(paths)}: {file_size/1048576:.1f}MB "
                  f"zonas={len(offsets)} sample={sample//1048576}MB/zona",
                  file=sys.stderr, flush=True)
            with open(cur_path, "rb") as f:
                for i, off in enumerate(offsets):
                    if time.monotonic() > deadline:
                        print(f"[strings] deadline en parte {part_idx+1} zona #{i}",
                              file=sys.stderr, flush=True)
                        return results
                    f.seek(off)
                    data = f.read(sample)
                    if not data:
                        continue
                    for m in _ASCII_PAT.finditer(data):
                        results.append(m.group().decode("ascii", errors="replace"))
                        if len(results) >= raw_cap or time.monotonic() > deadline:
                            return results
                    # UTF-16LE: strings de Windows/NTFS/Registro
                    for m in _UTF16LE_PAT.finditer(data):
                        s = _decode_utf16le(m.group())
                        if s and len(s) >= 8:
                            results.append(s)
                        if len(results) >= raw_cap or time.monotonic() > deadline:
                            return results
                    print(f"[strings] parte {part_idx+1} zona #{i}: {len(results)} strings "
                          f"({time.monotonic()-t0:.2f}s)", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[strings] EXCEPCIÓN en parte {part_idx+1}: {e}", file=sys.stderr, flush=True)
    return results


# ─── Parsers TSK ──────────────────────────────────────────────────────────────
_MMLS_SKIP = {"meta", "unalloc", "unpart", "extended", "primary table"}

def _mmls_partitions(mmls: str) -> list[tuple[int, int]]:
    """Devuelve lista de (start_sector, length_sectors) para todas las particiones
    de datos, ordenadas por tamaño descendente (la más grande primero)."""
    parts = []
    for line in mmls.splitlines():
        m = re.match(r'\s*\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)', line)
        if not m:
            continue
        desc = m.group(4).lower()
        if any(k in desc for k in _MMLS_SKIP):
            continue
        start  = int(m.group(1))
        length = int(m.group(3))
        if length > 0:
            parts.append((start, length))
    parts.sort(key=lambda x: -x[1])
    return parts


def _parse_offset(mmls: str) -> int | None:
    """Devuelve el sector de inicio de la partición MÁS GRANDE (datos principales)."""
    parts = _mmls_partitions(mmls)
    return parts[0][0] if parts else None


def _parse_fls(raw: str) -> list[dict]:
    """Parsea salida de fls.
    Body format (-m /): MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
    Regular format:     type inode:\tname [(deleted)]
    """
    files = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        entry: dict = {
            "raw": line, "type": "dir" if line.startswith("d") else "file",
            "deleted": "(deleted)" in line or "(deleted-realloc)" in line,
        }
        if len(parts) >= 9:
            # Body format: parts[0]=MD5, [1]=name, [2]=inode, [3]=mode,
            #              [4]=uid, [5]=gid, [6]=size, [7]=atime, [8]=mtime,
            #              [9]=ctime, [10]=crtime
            name = parts[1].strip()
            # Determinar tipo por el modo (parte [3]): comienza con 'd' = dir
            mode = parts[3].strip() if len(parts) > 3 else ""
            entry.update(
                name=name,
                inode=parts[2].strip(),
                mtime=parts[8].strip() if len(parts) > 8 else "—",
                atime=parts[7].strip() if len(parts) > 7 else "—",
                ctime=parts[9].strip() if len(parts) > 9 else "—",
                size=parts[6].strip() if len(parts) > 6 else "0",
            )
            if mode.startswith("d"):
                entry["type"] = "dir"
        else:
            m = re.search(r'\t(.+?)(?:\s+\(deleted(?:-realloc)?\))?$', line)
            entry["name"] = m.group(1).strip() if m else line
        files.append(entry)
    return files


# fls -r -d  output: "r/r * 27:\t/path/to/file (deleted)"
_FLS_DEL_RE = re.compile(
    r'^(?P<type_code>[a-z?])/[a-z?]\s+\*?\s*(?P<inode>\d+(?:-\d+)?):\s+(?P<path>.+?)(?:\s+\(deleted(?:-realloc)?\))?$'
)


def _parse_fls_del(raw: str) -> list[dict]:
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _FLS_DEL_RE.match(line)
        if m:
            name = m.group("path").lstrip("/")
            entries.append({
                "raw":    line,
                "name":   name or line,
                "inode":  m.group("inode"),
                "type":   "dir" if m.group("type_code") == "d" else "file",
            })
        else:
            # fallback: keep raw line but strip TSK type prefix if present
            clean = re.sub(r'^[a-z?]/[a-z?]\s+\*?\s*\d+(?:-\d+)?:\s*', '', line)
            entries.append({"raw": line, "name": clean or line, "inode": "—", "type": "file"})
    return entries


# ─── Detección de SO ──────────────────────────────────────────────────────────
_WIN_MARKERS = ["windows/system32", "program files", "users/", "programdata",
                "windows/prefetch", "windows/syswow64", "windows/temp",
                "windows/system32/winevt", "appdata/"]
_LIN_MARKERS = ["etc/passwd", "etc/shadow", "usr/bin", "usr/lib",
                "home/", "var/log", "boot/grub", "proc/", "/bin/bash"]
_MAC_MARKERS = ["library/preferences", "applications/", "system/library",
                "private/var", ".ds_store", "library/application support"]


def _detect_os(files: list[dict]) -> dict:
    sample = "\n".join(f.get("name", "").replace("\\", "/").lower()
                       for f in files[:3000])
    win = sum(1 for m in _WIN_MARKERS if m in sample)
    lin = sum(1 for m in _LIN_MARKERS if m in sample)
    mac = sum(1 for m in _MAC_MARKERS if m in sample)
    scores = {"Windows": win, "Linux": lin, "macOS": mac}
    best   = max(scores, key=scores.get)
    score  = scores[best]
    version = ""
    if best == "Windows":
        if "windows 11" in sample:
            version = "Windows 11"
        elif "windows 10" in sample:
            version = "Windows 10"
        elif "winsxs" in sample:
            version = "Windows Vista/7/8/10+"
    elif best == "Linux":
        for dist in ["ubuntu", "debian", "centos", "fedora", "arch", "kali"]:
            if dist in sample:
                version = dist.capitalize()
                break
    return {
        "os": best if score > 0 else "Desconocido",
        "version": version,
        "confidence": "alta" if score >= 3 else ("media" if score >= 1 else "baja"),
        "scores": scores,
    }


# ─── Clasificación por tipo ───────────────────────────────────────────────────
_FILE_CATS = {
    "Documentos":   {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                     ".txt", ".rtf", ".odt", ".ods", ".odp", ".csv"},
    "Imágenes":     {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".ico",
                     ".svg", ".webp", ".raw", ".cr2", ".nef", ".heic"},
    "Vídeos":       {".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".m4v", ".webm"},
    "Audio":        {".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a"},
    "Comprimidos":  {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab"},
    "Ejecutables":  {".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs",
                     ".sh", ".elf", ".msi", ".apk", ".jar"},
    "Bases de datos": {".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".sql"},
    "Logs":         {".log", ".evt", ".evtx"},
    "Configuración":{".ini", ".cfg", ".xml", ".json", ".yaml", ".yml", ".conf", ".reg"},
    "Email":        {".eml", ".msg", ".pst", ".ost", ".mbox"},
    "Web":          {".html", ".htm", ".js", ".css", ".php"},
    "Cripto":       {".pem", ".key", ".cer", ".crt", ".pfx", ".p12", ".kdbx"},
    "Sistema":      {".lnk", ".pf", ".dat", ".hve"},
    "Código":       {".py", ".c", ".cpp", ".java", ".cs", ".go", ".rs", ".ts",
                     ".rb", ".php", ".swift"},
}


def _classify_files(files: list[dict]) -> dict:
    result = {cat: {"count": 0, "extensions": {}, "sample": []} for cat in _FILE_CATS}
    result["Otros"] = {"count": 0, "extensions": {}, "sample": []}
    for f in files:
        if f.get("type") == "dir":
            continue
        ext = os.path.splitext(f.get("name", ""))[1].lower()
        bucket = "Otros"
        for cat, exts in _FILE_CATS.items():
            if ext in exts:
                bucket = cat
                break
        r = result[bucket]
        r["count"] += 1
        r["extensions"][ext] = r["extensions"].get(ext, 0) + 1
        if len(r["sample"]) < 50:
            r["sample"].append({"name": f.get("name", ""), "inode": f.get("inode"),
                                 "size": f.get("size"), "deleted": f.get("deleted", False)})
    return {k: v for k, v in result.items() if v["count"] > 0}


# ─── Usuarios ─────────────────────────────────────────────────────────────────
def _find_users(files: list[dict]) -> list[dict]:
    users: dict = {}
    SKIP = {"all users", "default", "default user", "public", "desktop.ini",
            ".", "..", "appdata"}
    for f in files:
        name = f.get("name", "").replace("\\", "/")
        for pat, os_name in [
            (r'[Uu]sers[/\\]+([^/\\]+)[/\\]', "Windows"),
            (r'^home[/\\]+([^/\\]+)[/\\]', "Linux"),
        ]:
            m = re.search(pat, name)
            if m:
                u = m.group(1)
                if u.lower() in SKIP:
                    break
                if u not in users:
                    users[u] = {"name": u, "os": os_name, "files": 0, "last_seen": ""}
                users[u]["files"] += 1
                t = f.get("mtime", "")
                if t and t > users[u]["last_seen"]:
                    users[u]["last_seen"] = t
                break
    return sorted(users.values(), key=lambda u: u["files"], reverse=True)


# ─── Ficheros sospechosos ────────────────────────────────────────────────────
_EXEC_EXTS   = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".sh", ".elf",
                ".scr", ".com", ".pif", ".cmd", ".hta", ".msi", ".jar"}
_FAKE_EXTS   = {".pdf", ".doc", ".docx", ".txt", ".jpg", ".jpeg", ".png",
                ".xls", ".xlsx", ".mp4", ".mp3", ".zip"}
_TOOL_NAMES  = {
    "mimikatz", "meterpreter", "netcat", "ncat", "cobalt",
    "pwdump", "fgdump", "wce.exe", "gsecdump", "beacon",
    "psexec", "winpeas", "linpeas", "lazagne", "crackmapexec",
    "bloodhound", "sharphound", "rubeus", "kerberoast", "responder",
    "covenant", "empire", "metasploit", "nmap", "masscan",
    "procdump", "lsass", "dumpert", "ntdsutil",
}
_CRED_KEYWORDS = [
    "password", "passwd", "credentials", "secret", "apikey", "api_key",
    "token", "private_key", "id_rsa", "id_ecdsa", "wallet.dat", ".kdbx",
    "shadow", "hashdump", "ntds.dit",
]
_SKIP_CRED_PATHS = ["/etc/skel", "system32", "sample", "template", "example"]


def _find_suspicious(files: list[dict]) -> list[dict]:
    result = []
    for f in files:
        name   = f.get("name", "")
        lower  = name.replace("\\", "/").lower()
        base   = os.path.basename(lower)
        parts  = base.split(".")
        ext    = ("." + parts[-1]) if len(parts) > 1 else ""
        reasons: list[str] = []

        # Doble extensión (.pdf.exe, .jpg.ps1, etc.)
        if len(parts) >= 3:
            fake = "." + parts[-2]
            if fake in _FAKE_EXTS and ext in _EXEC_EXTS:
                reasons.append(f"Doble extensión sospechosa: {fake}{ext}")

        # Ejecutable en directorio de descarga / temporal / caché
        if ext in _EXEC_EXTS:
            for loc in ["temp/", "tmp/", "downloads/", "appdata/local/temp",
                        "cache/", "recycler/", "$recycle.bin/", "appdata/roaming/microsoft/windows/recent"]:
                if loc in lower:
                    reasons.append(f"Ejecutable en ubicación no habitual: {loc.strip('/')}")
                    break

        # Herramientas de ataque / post-explotación
        if any(t in lower for t in _TOOL_NAMES):
            hit = next(t for t in _TOOL_NAMES if t in lower)
            reasons.append(f"Herramienta de ataque conocida: {hit}")

        # Credenciales y secretos
        if ext == ".kdbx":
            reasons.append("Base de datos KeePass (credenciales)")
        for kw in _CRED_KEYWORDS:
            if kw in lower and not any(s in lower for s in _SKIP_CRED_PATHS):
                reasons.append(f"Posible fichero de credenciales ({kw})")
                break

        # Script oculto (punto inicial en Unix)
        if base.startswith(".") and ext in {".sh", ".py", ".rb", ".pl", ".php"}:
            reasons.append("Script oculto (nombre comienza con punto)")

        # Ejecutable eliminado (recuperable forense)
        if ext in _EXEC_EXTS and f.get("deleted"):
            reasons.append("Ejecutable eliminado — recuperable para análisis")

        # Ejecutable en raíz del filesystem o en ruta inusual para binarios
        if ext in {".exe", ".dll", ".scr"} and lower.count("/") <= 2:
            if not any(p in lower for p in ["windows/", "program files", "system32", "syswow64"]):
                reasons.append("Ejecutable en ruta de raíz — no es ubicación estándar")

        # Fichero .scr (screen saver usado como malware)
        if ext == ".scr" and "system32" not in lower:
            reasons.append("Protector de pantalla (.scr) fuera de System32")

        # Nombre con muchos caracteres aleatorios (posible ofuscación)
        stem = parts[0] if parts else base
        if len(stem) >= 12 and ext in _EXEC_EXTS:
            alpha  = sum(c.isalpha() for c in stem)
            digit  = sum(c.isdigit() for c in stem)
            if alpha > 0 and digit / len(stem) > 0.5:
                reasons.append("Nombre con alta proporción de dígitos (posible ofuscación)")

        # NTDS.dit — base de datos de Active Directory
        if "ntds.dit" in lower:
            reasons.append("Copia de NTDS.dit — contiene hashes de contraseñas de AD")

        # SAM exportado fuera de su ubicación normal
        if base == "sam" and "config" not in lower and "system32" not in lower:
            reasons.append("Fichero SAM fuera de su ubicación estándar")

        if reasons:
            result.append({
                "name":    os.path.basename(name),
                "path":    name,
                "inode":   f.get("inode", "—"),
                "size":    f.get("size", "0"),
                "mtime":   f.get("mtime", ""),
                "deleted": f.get("deleted", False),
                "reasons": reasons,
            })
    return result[:2000]


# ─── Artefactos navegador ─────────────────────────────────────────────────────
def _find_browser_dbs(files: list[dict]) -> dict:
    dbs = []
    for f in files:
        if f.get("type") == "dir":
            continue
        path  = f.get("name", "").replace("\\", "/").lower()
        base  = os.path.basename(path)
        size  = int(f.get("size") or 0)

        browser = None
        if "chrome" in path:   browser = "Chrome"
        elif "edge" in path:   browser = "Edge"
        elif "brave" in path:  browser = "Brave"
        elif "firefox" in path: browser = "Firefox"
        elif "opera" in path:  browser = "Opera"
        elif "safari" in path: browser = "Safari"

        if not browser:
            continue

        if base in ("history", "places.sqlite") and size > 0:
            dbs.append({"type": "history", "browser": browser,
                        "path": f.get("name"), "inode": f.get("inode"),
                        "size": size})
        elif base in ("cookies", "cookies.sqlite") and size > 0:
            dbs.append({"type": "cookies", "browser": browser,
                        "path": f.get("name"), "inode": f.get("inode"),
                        "size": size})
        elif base == "bookmarks" and size > 0:
            dbs.append({"type": "bookmarks", "browser": browser,
                        "path": f.get("name"), "inode": f.get("inode"),
                        "size": size})
    return {"dbs": dbs}


# ─── Actividad reciente (LNK, Prefetch, hives) ───────────────────────────────
def _find_recent_activity(files: list[dict]) -> dict:
    result = {"lnk": [], "prefetch": [], "registry_hives": []}
    REG_HIVES = {"ntuser.dat", "sam", "system", "software", "security",
                 "default", "usrclass.dat"}
    for f in files:
        if f.get("type") == "dir":
            continue
        name  = f.get("name", "")
        lower = name.replace("\\", "/").lower()
        base  = os.path.basename(lower)
        ext   = os.path.splitext(base)[1]

        if ext == ".lnk":
            result["lnk"].append({
                "name": os.path.basename(name), "path": name,
                "inode": f.get("inode"), "size": f.get("size"),
                "mtime": f.get("mtime"), "deleted": f.get("deleted", False),
            })

        elif ext == ".pf" and "prefetch" in lower:
            pf_base = os.path.basename(name)
            parts   = pf_base.rsplit("-", 1)
            exe     = parts[0] if len(parts) == 2 else pf_base.replace(".pf", "").replace(".PF", "")
            result["prefetch"].append({
                "name": pf_base, "exe": exe, "path": name,
                "inode": f.get("inode"), "mtime": f.get("mtime"),
            })

        elif base in REG_HIVES:
            result["registry_hives"].append({
                "name": base.upper(), "path": name,
                "inode": f.get("inode"), "size": f.get("size"),
            })

    return result


# ─── Registros de eventos ────────────────────────────────────────────────────
_EVTX_CHANNELS = {
    "security":       "Seguridad",
    "system":         "Sistema",
    "application":    "Aplicación",
    "setup":          "Instalación",
    "microsoft-windows-sysmon%4operational":                    "Sysmon",
    "microsoft-windows-powershell%4operational":                "PowerShell",
    "microsoft-windows-taskscheduler%4operational":             "Programador de tareas",
    "microsoft-windows-terminalservices-remoteconnectionmanager%4operational": "RDP Conexiones",
    "microsoft-windows-bits-client%4operational":               "BITS (descargas en segundo plano)",
    "microsoft-windows-wlan-autoconfig%4operational":           "WiFi",
    "microsoft-windows-windows-defender%4operational":          "Windows Defender",
    "microsoft-windows-winlogon%4operational":                  "Winlogon",
    "microsoft-windows-user profile service%4operational":      "Perfil de usuario",
    "microsoft-windows-ntlm%4operational":                      "NTLM",
}

def _find_event_logs(files: list[dict]) -> list[dict]:
    result = []
    for f in files:
        if f.get("type") == "dir":
            continue
        name  = f.get("name", "")
        lower = name.replace("\\", "/").lower()
        base  = os.path.basename(lower)
        ext   = os.path.splitext(base)[1]
        if ext not in (".evtx", ".evt"):
            continue
        stem    = os.path.splitext(base)[0]
        channel = _EVTX_CHANNELS.get(stem, stem.replace("%4", "/").replace("-", " ").title())
        result.append({
            "name":    os.path.basename(name),
            "path":    name,
            "channel": channel,
            "format":  ext.upper().lstrip("."),
            "inode":   f.get("inode"),
            "size":    f.get("size"),
            "mtime":   f.get("mtime"),
            "deleted": f.get("deleted", False),
        })
    return sorted(result, key=lambda x: (x.get("deleted", False), x.get("name", "")))


# ─── Artefactos de correo electrónico ────────────────────────────────────────
_EMAIL_FORMATS = {
    ".eml": "EML (mensaje individual)",
    ".msg": "MSG (Outlook)",
    ".pst": "PST (buzón Outlook)",
    ".ost": "OST (caché Outlook)",
    ".mbox": "MBOX (Unix/Thunderbird)",
    ".dbx": "DBX (Outlook Express)",
    ".nsf": "NSF (Lotus Notes)",
    ".emlx": "EMLX (Apple Mail)",
}

def _find_email_files(files: list[dict]) -> list[dict]:
    result = []
    for f in files:
        if f.get("type") == "dir":
            continue
        name = f.get("name", "")
        ext  = os.path.splitext(name)[1].lower()
        if ext not in _EMAIL_FORMATS:
            continue
        result.append({
            "name":    os.path.basename(name),
            "path":    name,
            "format":  _EMAIL_FORMATS[ext],
            "inode":   f.get("inode"),
            "size":    f.get("size"),
            "mtime":   f.get("mtime"),
            "deleted": f.get("deleted", False),
        })
    return sorted(result, key=lambda x: (x.get("deleted", False), x.get("name", "")))


# ─── Artefactos de red ────────────────────────────────────────────────────────
_NET_FILENAMES = {
    "hosts":                 "Fichero hosts (resolución DNS local)",
    "networks":              "Tabla de redes",
    "interfaces":            "Configuración de interfaces",
    "wpa_supplicant.conf":   "Perfiles WiFi (Linux)",
    "resolv.conf":           "Configuración DNS (Linux)",
    "nsswitch.conf":         "Resolución de nombres",
    "known_hosts":           "Hosts SSH conocidos",
    "authorized_keys":       "Claves SSH autorizadas",
}
_NET_PATH_PATTERNS = [
    ("wifintwk",                                 "Perfil de red WiFi"),
    ("wlan/profiles",                            "Perfil WiFi (Windows)"),
    ("network/profiles",                         "Perfil de red"),
    ("microsoft/windows/recently used wlan",     "Redes WiFi recientes"),
    ("vpn",                                      "Configuración VPN"),
    ("openvpn",                                  "Configuración OpenVPN"),
    ("remotedesktop",                            "Configuración RDP"),
]

def _find_network_artifacts(files: list[dict]) -> list[dict]:
    result = []
    seen: set[str] = set()
    for f in files:
        if f.get("type") == "dir":
            continue
        name  = f.get("name", "")
        lower = name.replace("\\", "/").lower()
        base  = os.path.basename(lower)

        desc = _NET_FILENAMES.get(base, "")
        if not desc:
            for pat, label in _NET_PATH_PATTERNS:
                if pat in lower:
                    ext = os.path.splitext(base)[1]
                    if ext in (".xml", ".conf", ".profile", ".pbk", "") or not ext:
                        desc = label
                        break

        if desc and name not in seen:
            seen.add(name)
            result.append({
                "name":        os.path.basename(name),
                "path":        name,
                "description": desc,
                "inode":       f.get("inode"),
                "size":        f.get("size"),
                "mtime":       f.get("mtime"),
            })
    return result


# ─── Papelera de reciclaje ────────────────────────────────────────────────────
def _find_recycle_bin(files: list[dict]) -> list[dict]:
    result = []
    for f in files:
        name  = f.get("name", "")
        lower = name.replace("\\", "/").lower()
        if not ("$recycle.bin" in lower or "recycler/" in lower or "/recycled/" in lower):
            continue
        base      = os.path.basename(name)
        base_low  = base.lower()
        if base_low.startswith("$i"):
            entry_type = "metadata"
        elif base_low.startswith("$r"):
            entry_type = "contenido"
        elif base_low == "desktop.ini":
            continue
        else:
            entry_type = "entrada"
        result.append({
            "name":       base,
            "path":       name,
            "entry_type": entry_type,
            "type":       f.get("type"),
            "inode":      f.get("inode"),
            "size":       f.get("size"),
            "mtime":      f.get("mtime"),
            "deleted":    f.get("deleted", False),
        })
    return sorted(result, key=lambda x: x.get("name", ""))


# ─── Detección de dispositivos USB (por trazas en el filesystem) ─────────────
_USB_PATH_PATTERNS = [
    "usbstore",
    "usbstor",
    "removablemedia",
    "setupapi",
]

def _find_usb_traces(files: list[dict]) -> list[dict]:
    """Detecta trazas de dispositivos USB a partir de rutas del filesystem."""
    result = []
    seen: set[str] = set()
    for f in files:
        name  = f.get("name", "")
        lower = name.replace("\\", "/").lower()
        base  = os.path.basename(lower)
        if any(p in lower for p in _USB_PATH_PATTERNS):
            if name not in seen:
                seen.add(name)
                result.append({
                    "name":  os.path.basename(name),
                    "path":  name,
                    "inode": f.get("inode"),
                    "size":  f.get("size"),
                    "mtime": f.get("mtime"),
                })
        # setupapi.dev.log contiene historial de instalación de dispositivos
        if base in ("setupapi.dev.log", "setupapi.setup.log"):
            if name not in seen:
                seen.add(name)
                result.append({
                    "name":  os.path.basename(name),
                    "path":  name,
                    "inode": f.get("inode"),
                    "size":  f.get("size"),
                    "mtime": f.get("mtime"),
                })
    return result


# ─── Detección de elementos de inicio automático ─────────────────────────────
_STARTUP_PATHS = [
    "startup",
    "start menu",
    "autorun",
    "currentversion/run",
    "windows/start menu",
]

def _find_startup_items(files: list[dict]) -> list[dict]:
    """Detecta ficheros en ubicaciones de inicio automático."""
    result = []
    for f in files:
        if f.get("type") == "dir":
            continue
        name  = f.get("name", "")
        lower = name.replace("\\", "/").lower()
        if any(p in lower for p in _STARTUP_PATHS):
            ext = os.path.splitext(name)[1].lower()
            if ext in {".lnk", ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll", ".scr"}:
                result.append({
                    "name":    os.path.basename(name),
                    "path":    name,
                    "inode":   f.get("inode"),
                    "size":    f.get("size"),
                    "mtime":   f.get("mtime"),
                    "deleted": f.get("deleted", False),
                })
    return result


# ─── Parseo de historial Chrome (SQLite) ─────────────────────────────────────
def _chrome_ts(us: int) -> str:
    import datetime
    try:
        return (datetime.datetime(1601, 1, 1) +
                datetime.timedelta(microseconds=us)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(us)


def _parse_chrome_db(data: bytes) -> dict:
    import sqlite3 as _sq
    res = {"visits": [], "downloads": [], "searches": []}
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tf:
            tf.write(data); tmp = tf.name
        uri = f"file:{tmp}?mode=ro&immutable=1"
        con = _sq.connect(uri, uri=True)
        con.row_factory = _sq.Row
        try:
            rows = con.execute(
                "SELECT u.url, u.title, u.visit_count, v.visit_time "
                "FROM urls u JOIN visits v ON u.id=v.url "
                "ORDER BY v.visit_time DESC LIMIT 500"
            ).fetchall()
            res["visits"] = [{"url": r["url"][:500], "title": (r["title"] or "")[:200],
                               "count": r["visit_count"], "time": _chrome_ts(r["visit_time"])}
                              for r in rows]
        except Exception:
            pass
        try:
            rows = con.execute(
                "SELECT current_path, target_path, total_bytes, start_time "
                "FROM downloads ORDER BY start_time DESC LIMIT 200"
            ).fetchall()
            res["downloads"] = [{"path": (r["current_path"] or r["target_path"] or "")[:300],
                                  "size": r["total_bytes"],
                                  "time": _chrome_ts(r["start_time"])} for r in rows]
        except Exception:
            pass
        try:
            rows = con.execute(
                "SELECT term FROM keyword_search_terms ORDER BY last_visit_time DESC LIMIT 200"
            ).fetchall()
            res["searches"] = list({r["term"] for r in rows if r["term"]})
        except Exception:
            pass
        con.close()
    except Exception:
        pass
    finally:
        if tmp:
            try: os.unlink(tmp)
            except Exception: pass
    return res


def _parse_firefox_db(data: bytes) -> dict:
    import sqlite3 as _sq, datetime
    res = {"visits": [], "downloads": [], "searches": []}
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tf:
            tf.write(data); tmp = tf.name
        con = _sq.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True)
        con.row_factory = _sq.Row
        def fts(us):
            try:
                return datetime.datetime.utcfromtimestamp(
                    us / 1_000_000).strftime("%Y-%m-%d %H:%M:%S")
            except Exception: return str(us)
        try:
            rows = con.execute(
                "SELECT p.url, p.title, p.visit_count, h.visit_date "
                "FROM moz_places p JOIN moz_historyvisits h ON p.id=h.place_id "
                "ORDER BY h.visit_date DESC LIMIT 500"
            ).fetchall()
            res["visits"] = [{"url": r["url"][:500], "title": (r["title"] or "")[:200],
                               "count": r["visit_count"], "time": fts(r["visit_date"])}
                              for r in rows]
        except Exception:
            pass
        con.close()
    except Exception:
        pass
    finally:
        if tmp:
            try: os.unlink(tmp)
            except Exception: pass
    return res


def _extract_browser_history(image_path: str, dbs: list[dict],
                              img_offset: int) -> dict:
    if not HAS_PYTSK3:
        return {"visits": [], "downloads": [], "searches": [],
                "note": "Requiere pytsk3 para extracción directa"}
    try:
        import pytsk3
        img = pytsk3.Img_Info(image_path)
        fs  = pytsk3.FS_Info(img, offset=img_offset * 512)
    except Exception as e:
        return {"visits": [], "downloads": [], "searches": [], "note": str(e)}

    all_v, all_d, all_s = [], [], []
    for db in [d for d in dbs if d.get("type") == "history"][:5]:
        try:
            inode = int(db["inode"])
            size  = int(db.get("size") or 0)
            f     = fs.open_meta(inode=inode)
            data  = f.read_random(0, min(size, 20 * 1024 * 1024))
            parsed = (_parse_firefox_db(data) if db.get("browser") == "Firefox"
                      else _parse_chrome_db(data))
            for v in parsed.get("visits", []):
                v["browser"] = db.get("browser", "?")
                all_v.append(v)
            all_d.extend(parsed.get("downloads", []))
            all_s.extend(parsed.get("searches", []))
        except Exception:
            continue

    seen = set()
    uniq_v = []
    for v in sorted(all_v, key=lambda x: x.get("time", ""), reverse=True):
        if v["url"] not in seen:
            seen.add(v["url"]); uniq_v.append(v)
    return {"visits": uniq_v[:500], "downloads": all_d[:200],
            "searches": list(set(all_s))[:200]}


# ─── Inode metadata ───────────────────────────────────────────────────────────
def get_inode_metadata(image_path: str, inode: str, offset: int | None = None,
                       split_parts: list[str] | None = None) -> dict:
    if HAS_PYTSK3:
        try:
            import pytsk3
            img_url = (",".join(split_parts)
                       if split_parts and len(split_parts) > 1 else image_path)
            img = pytsk3.Img_Info(img_url)
            fs  = pytsk3.FS_Info(img, offset=(offset or 0) * 512)
            f   = fs.open_meta(inode=int(inode))
            m   = f.info.meta
            return {"istat": (
                f"Inode    : {m.addr}\n"
                f"Tipo     : {m.type}\n"
                f"Tamaño   : {m.size:,} bytes\n"
                f"UID/GID  : {m.uid} / {m.gid}\n"
                f"Modo     : {oct(m.mode)}\n"
                f"mtime    : {m.mtime}\n"
                f"atime    : {m.atime}\n"
                f"ctime    : {m.ctime}\n"
                f"Flags    : {m.flags}"
            )}
        except Exception as e:
            return {"istat": f"Error: {e}"}
    out = _tsk_cmd(["istat"], image_path, offset, extra=[inode], split_parts=split_parts)
    return {"istat": out or "Sin datos"}


# ─── Entry point ─────────────────────────────────────────────────────────────
def analyze_image(image_path: str, progress_cb=None) -> dict:
    import time as _t

    def _log(msg: str):
        if progress_cb:
            progress_cb(msg)

    t0 = _t.monotonic()

    # ── Detectar imagen split (.001/.002/.003…) ──────────────────────────────
    split_parts = _gather_split_parts(image_path)
    is_split    = len(split_parts) > 1
    if is_split:
        total_mb = sum(os.path.getsize(p) for p in split_parts) / 1_048_576
        _log(f"Imagen split detectada: {len(split_parts)} partes ({total_mb:.1f} MB total)")

    _log("Calculando hashes...")
    hashes = _compute_hashes(image_path, split_parts=split_parts if is_split else None)
    _log(f"Hashes: MD5={hashes.get('md5','?')[:8]}... ({_t.monotonic()-t0:.1f}s)")

    img_type = _detect_image_type(image_path)
    _log(f"Tipo imagen: {img_type.get('type','?')}")

    if img_type.get("unsupported"):
        if img_type.get("extractable") and HAS_7ZIP:
            _log(f"[extract] Archivo {img_type.get('fmt','comprimido')} detectado — extrayendo imagen interna...")
            extracted_path, tmpdir = _extract_image_from_archive(image_path, _log)
            if extracted_path and tmpdir:
                try:
                    _log(f"[extract] Analizando imagen extraída: {Path(extracted_path).name}")
                    result = analyze_image(extracted_path, progress_cb=progress_cb)
                    result["archive_source"] = Path(image_path).name
                    result["hashes_archive"] = hashes
                    return result
                finally:
                    shutil.rmtree(tmpdir, ignore_errors=True)
                    _log("[extract] Directorio temporal limpiado")
            _log("[extract] Extracción fallida — si es un archivo multiparte, sube todos los volúmenes (.001, .002, .003...)")

        err = img_type.get("error", "Formato no soportado")
        _log(f"[ERROR] {err}")
        return {
            "error": err,
            "image_type": img_type.get("type"),
            "hashes": hashes,
            "files": [], "deleted": [], "strings": {},
            "total_files": 0, "total_deleted": 0,
            "backend": "none",
        }

    entropy  = _estimate_entropy(image_path,
                                  split_parts=split_parts if is_split else None)
    _log(f"Entropía: {entropy}")

    if HAS_PYTSK3:
        _log("Analizando con pytsk3...")
        data = _pytsk3_analyze(image_path, split_parts=split_parts if is_split else None)
        if not data.get("files") and (HAS_TSK_FLS or HAS_WSL):
            _log("pytsk3 no encontró ficheros — intentando WSL/TSK como fallback...")
            tsk_data = _tsk_analyze(image_path, split_parts=split_parts if is_split else None)
            if tsk_data.get("files"):
                data = tsk_data
                _log(f"Fallback WSL/TSK encontró {len(data['files'])} ficheros")
    elif HAS_TSK_FLS or HAS_WSL:
        _log(f"Analizando con {'tsk_binaries' if HAS_TSK_FLS else 'wsl+sleuthkit'}...")
        data = _tsk_analyze(image_path, split_parts=split_parts if is_split else None)
    elif HAS_7ZIP or True:  # pycdlib always available if installed
        _log("Analizando con pycdlib / 7-Zip (modo básico)...")
        data = _pycdlib_analyze(image_path)
        if not data or data.get("total_files", 0) == 0:
            data = _7zip_analyze(image_path)
        if not data:
            data = {
                "backend": "none", "files": [], "deleted": [],
                "total_files": 0, "total_deleted": 0,
                "image_info": {}, "strings": {}, "detected_offset": None,
            }
        else:
            data["backend"] = "7zip"
    else:
        _log("Sin backend forense — devolviendo análisis básico")
        data = {
            "backend": "none",
            "error": (
                "No se encontró ningún backend forense.\n"
                "Opciones:\n"
                "  - pip install pytsk3\n"
                "  - wsl --install  (Windows, luego: wsl -e sudo apt install sleuthkit)\n"
                "  - sudo apt install sleuthkit  (Linux)\n"
                "  - Instalar 7-Zip desde https://7-zip.org (análisis básico)\n"
                "Con backend=none solo se calculan hashes, entropía y strings."
            ),
            "files": [], "deleted": [], "total_files": 0, "total_deleted": 0,
            "image_info": {}, "strings": {}, "detected_offset": None,
        }

    _log(f"Ficheros encontrados: {len(data.get('files', []))} | Eliminados: {len(data.get('deleted', []))}")

    # ── Artefactos desde listado de ficheros ─────────────────────────────────
    all_files  = data.get("files", [])
    img_offset = data.get("detected_offset") or 0

    _log("Detectando sistema operativo...")
    data["os_info"]          = _detect_os(all_files)
    _log(f"SO detectado: {data['os_info'].get('os','?')} (confianza: {data['os_info'].get('confidence','?')})")

    _log("Clasificando tipos de fichero...")
    data["file_types"]       = _classify_files(all_files)

    _log("Buscando usuarios...")
    data["users"]            = _find_users(all_files)
    _log(f"Usuarios encontrados: {len(data['users'])}")

    _log("Buscando ficheros sospechosos...")
    data["suspicious_files"] = _find_suspicious(all_files)
    _log(f"Ficheros sospechosos: {len(data['suspicious_files'])}")

    _log("Buscando artefactos de navegador...")
    data["browser_dbs"]      = _find_browser_dbs(all_files)

    _log("Buscando actividad reciente (LNK, Prefetch, hives)...")
    data["recent_activity"]  = _find_recent_activity(all_files)

    _log("Buscando registros de eventos...")
    data["event_logs"]       = _find_event_logs(all_files)
    _log(f"Registros de eventos: {len(data['event_logs'])}")

    _log("Buscando artefactos de correo...")
    data["email_files"]      = _find_email_files(all_files)
    _log(f"Ficheros de correo: {len(data['email_files'])}")

    _log("Buscando artefactos de red...")
    data["network_artifacts"] = _find_network_artifacts(all_files)

    _log("Analizando papelera de reciclaje...")
    data["recycle_bin"]      = _find_recycle_bin(all_files)
    _log(f"Entradas en papelera: {len(data['recycle_bin'])}")

    _log("Buscando trazas de dispositivos USB...")
    data["usb_traces"]       = _find_usb_traces(all_files)

    _log("Buscando elementos de inicio automático...")
    data["startup_items"]    = _find_startup_items(all_files)

    # ── Historial de navegador (requiere pytsk3) ─────────────────────────────
    browser_dbs = data["browser_dbs"].get("dbs", [])
    if HAS_PYTSK3 and browser_dbs:
        _log(f"Extrayendo historial de navegador ({len(browser_dbs)} DBs)...")
        data["browser_history"] = _extract_browser_history(
            image_path, browser_dbs, img_offset)
        _log(f"Visitas: {len(data['browser_history'].get('visits',[]))}")
    else:
        data["browser_history"] = {"visits": [], "downloads": [], "searches": []}

    _log("Extrayendo strings e IOCs...")
    if "strings" not in data or not data["strings"]:
        data["strings"] = _extract_strings(image_path,
                                            split_parts=split_parts if is_split else None)
    _log(f"Strings: URLs={len(data['strings'].get('urls',[]))} emails={len(data['strings'].get('emails',[]))} IPs={len(data['strings'].get('ips',[]))}")

    elapsed = _t.monotonic() - t0
    _log(f"Análisis completo en {elapsed:.1f}s")

    data["platform"]     = platform.system()
    data["arch"]         = platform.machine()
    data["hashes"]       = hashes
    data["image_type"]   = img_type
    data["entropy"]      = entropy
    if is_split:
        data["split_parts"] = split_parts
        data["split_count"] = len(split_parts)
    data["backend_info"] = {
        "pytsk3":  HAS_PYTSK3,
        "tsk_bin": bool(HAS_TSK_FLS),
        "wsl":     HAS_WSL,
        "7zip":    HAS_7ZIP,
        "active":  data.get("backend", BACKEND),
    }
    return data
