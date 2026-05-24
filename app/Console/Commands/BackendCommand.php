<?php

namespace App\Console\Commands;

use App\Console\Concerns\ManagesPythonBackend;
use Illuminate\Console\Command;
use Symfony\Component\Process\Process;

class BackendCommand extends Command
{
    use ManagesPythonBackend;

    protected $signature   = 'backend:start';
    protected $description = 'Inicia el backend Python (FastAPI) de LeerDD';

    public function handle(): void
    {
        $backendDir = base_path('LeerDD');
        $python     = $this->findPython();

        if (! $python) {
            $this->error('Python 3 no encontrado. Instálalo antes de continuar.');
            return;
        }

        $this->line("  Python: {$python}");
        $this->line('  Instalando dependencias...');
        $this->installDeps($python, $backendDir);

        $port = (int) config('forensic.backend_port', 8001);
        $this->info("  Iniciando FastAPI en puerto {$port}");
        $this->line("  URL:  http://localhost:{$port}");
        $this->line("  Docs: http://localhost:{$port}/docs");
        $this->line('');

        $process = new Process(
            [
                $python, '-m', 'uvicorn', 'main:app',
                '--host', '0.0.0.0',
                '--port', (string) $port,
                '--reload',
                '--no-access-log',
                '--log-level', 'warning',
            ],
            $backendDir,
            null,
            null,
            null
        );

        $process->start(function ($type, $buffer) {
            if ($type === Process::ERR && str_contains($buffer, 'ERROR')) {
                $this->error(trim($buffer));
            }
        });

        \file_put_contents(storage_path('app/backend.pid'), $process->getPid());

        $process->wait();
    }
}
