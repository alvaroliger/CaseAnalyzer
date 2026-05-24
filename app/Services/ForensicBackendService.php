<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ForensicBackendService
{
    private string $baseUrl;
    private int    $timeout;

    public function __construct()
    {
        $this->baseUrl = rtrim(config('forensic.backend_url', 'http://localhost:8001'), '/');
        $this->timeout = (int) config('forensic.timeout', 7260);
    }

    public function health(): array
    {
        try {
            $res  = Http::timeout(4)->get("{$this->baseUrl}/health");
            $data = $res->json() ?? [];
            if ($res->successful() && isset($data['status'])) {
                return $data;
            }
            return ['status' => 'error', 'error' => 'Respuesta inesperada del backend'];
        } catch (\Throwable $e) {
            return ['status' => 'offline', 'error' => $e->getMessage(), 'platform' => PHP_OS_FAMILY];
        }
    }

    /**
     * Envía uno o más archivos al backend Python y retorna el análisis completo.
     *
     * @param  string  $primaryPath  Ruta local al archivo principal
     * @param  string  $filename     Nombre original del archivo principal
     * @param  array   $extras       [ ['path'=>..., 'name'=>...] ] archivos adicionales
     * @throws \RuntimeException
     */
    public function analyze(string $primaryPath, string $filename, array $extras = []): array
    {
        if (! file_exists($primaryPath) || ! is_readable($primaryPath)) {
            throw new \RuntimeException("El archivo temporal no existe o no se puede leer: {$primaryPath}");
        }

        $handles = [];
        try {
            $fh = fopen($primaryPath, 'r');
            if (! $fh) {
                throw new \RuntimeException("No se pudo abrir el archivo: {$primaryPath}");
            }
            $handles[] = $fh;

            $request = Http::timeout($this->timeout)->attach('files', $fh, $filename);

            foreach ($extras as $extra) {
                if (! file_exists($extra['path']) || ! is_readable($extra['path'])) {
                    continue;
                }
                $efh = fopen($extra['path'], 'r');
                if ($efh) {
                    $handles[]  = $efh;
                    $request    = $request->attach('files', $efh, $extra['name']);
                }
            }

            $response = $request->post("{$this->baseUrl}/analyze");

            if ($response->failed()) {
                $body   = $response->json();
                $detail = $body['detail'] ?? ($body['error'] ?? 'Error desconocido del backend');
                throw new \RuntimeException($detail);
            }

            $result = $response->json();
            if (! is_array($result)) {
                throw new \RuntimeException('La respuesta del backend no es un JSON válido');
            }

            return $result;

        } catch (\Illuminate\Http\Client\ConnectionException $e) {
            throw new \RuntimeException(
                "No se puede conectar al backend Python en {$this->baseUrl}. " .
                "Ejecuta: php artisan serve  (arranca Laravel + Python juntos)",
                0, $e
            );
        } catch (\RuntimeException $e) {
            throw $e;
        } catch (\Throwable $e) {
            Log::error('ForensicBackendService::analyze error', [
                'message'  => $e->getMessage(),
                'file'     => $e->getFile(),
                'line'     => $e->getLine(),
                'filename' => $filename,
            ]);
            throw new \RuntimeException('Error interno analizando imagen: ' . $e->getMessage(), 0, $e);
        } finally {
            foreach ($handles as $h) {
                if (is_resource($h)) {
                    fclose($h);
                }
            }
        }
    }

    public function fileContent(string $fileId, int $inode, int $maxBytes = 65536): array
    {
        try {
            $res = Http::timeout(30)->get(
                "{$this->baseUrl}/file/{$fileId}/{$inode}",
                ['max_bytes' => $maxBytes]
            );
            return $res->json() ?? ['error' => 'Sin datos'];
        } catch (\Throwable $e) {
            return ['error' => $e->getMessage()];
        }
    }

    public function inodeMetadata(string $fileId, string $inode, ?int $offset = null): array
    {
        $params = $offset !== null ? ['offset' => $offset] : [];
        try {
            $res = Http::timeout(15)->get("{$this->baseUrl}/metadata/{$fileId}/{$inode}", $params);
            return $res->json() ?? ['istat' => 'Sin datos'];
        } catch (\Throwable $e) {
            return ['istat' => 'Error: ' . $e->getMessage()];
        }
    }

    public function getLog(string $fileId): array
    {
        try {
            $res = Http::timeout(10)->get("{$this->baseUrl}/logs/{$fileId}");
            if ($res->successful()) {
                return $res->json() ?? ['error' => 'Sin datos'];
            }
            return ['error' => 'Log no encontrado'];
        } catch (\Throwable $e) {
            return ['error' => $e->getMessage()];
        }
    }

    public function cleanup(string $fileId): bool
    {
        try {
            $res = Http::timeout(5)->delete("{$this->baseUrl}/cleanup/{$fileId}");
            return $res->successful();
        } catch (\Throwable) {
            return false;
        }
    }
}
