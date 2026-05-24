<?php

namespace App\Http\Controllers;

use App\Services\ForensicBackendService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class CaseController extends Controller
{
    public function __construct(private ForensicBackendService $backend) {}

    public function index(): \Illuminate\View\View
    {
        $health = $this->backend->health();
        return view('analyzer', compact('health'));
    }

    public function health(): JsonResponse
    {
        return response()->json($this->backend->health());
    }

    public function analyze(Request $request): JsonResponse
    {
        $request->validate([
            'files' => 'required|array|min:1|max:20',
            'files.*' => [
                'required', 'file',
                function ($attr, $value, $fail) {
                    $ext     = strtolower($value->getClientOriginalExtension());
                    $allowed = config('forensic.allowed_extensions', ['dd', 'img', 'raw', 'iso', 'e01', '001', 'bin']);
                    if (! \in_array($ext, $allowed) && ! preg_match('/^\d{3}$/', $ext)) {
                        $fail("Extensión .{$ext} no soportada.");
                    }
                },
            ],
        ]);

        $uploadedFiles = $request->file('files');
        $primary       = $uploadedFiles[0];
        $filename      = $primary->getClientOriginalName();

        try {
            $multipartPaths = array_map(
                fn($f) => ['path' => $f->getRealPath(), 'name' => $f->getClientOriginalName()],
                $uploadedFiles
            );

            $result = $this->backend->analyze($multipartPaths[0]['path'], $filename, array_slice($multipartPaths, 1));

            try {
                session(['last_analysis' => [
                    'filename'      => $filename,
                    'file_id'       => $result['file_id'] ?? null,
                    'total_files'   => $result['total_files'] ?? 0,
                    'total_deleted' => $result['total_deleted'] ?? 0,
                    'backend'       => $result['backend_info']['active'] ?? '—',
                    'analyzed_at'   => now()->format('d/m/Y H:i:s'),
                ]]);
            } catch (\Throwable) {}

            return response()->json($result);
        } catch (\RuntimeException $e) {
            return response()->json(['error' => $e->getMessage()], 503);
        } catch (\Throwable $e) {
            return response()->json(['error' => 'Error interno: ' . $e->getMessage()], 500);
        }
    }

    public function fileContent(string $fileId, int $inode, Request $request): JsonResponse
    {
        if ($err = $this->validateFileId($fileId)) {
            return $err;
        }
        $maxBytes = min((int) $request->get('max_bytes', 65536), 10 * 1024 * 1024);
        return response()->json($this->backend->fileContent($fileId, $inode, $maxBytes));
    }

    public function metadata(string $fileId, string $inode, Request $request): JsonResponse
    {
        if ($err = $this->validateFileId($fileId)) {
            return $err;
        }
        if (! preg_match('/^\d{1,10}$/', $inode)) {
            return response()->json(['error' => 'inode inválido'], 422);
        }
        $offset = $request->integer('offset', 0) ?: null;
        return response()->json($this->backend->inodeMetadata($fileId, $inode, $offset));
    }

    public function cleanup(string $fileId): JsonResponse
    {
        if ($err = $this->validateFileId($fileId)) {
            return $err;
        }
        return response()->json(['deleted' => $this->backend->cleanup($fileId)]);
    }

    public function analysisLog(string $fileId): JsonResponse
    {
        if ($err = $this->validateFileId($fileId)) {
            return $err;
        }
        $data = $this->backend->getLog($fileId);
        return response()->json($data, isset($data['error']) ? 404 : 200);
    }

    private function validateFileId(string $fileId): ?JsonResponse
    {
        if (! preg_match('/^[a-f0-9\-]{1,40}$/i', $fileId)) {
            return response()->json(['error' => 'fileId inválido'], 422);
        }
        return null;
    }
}
