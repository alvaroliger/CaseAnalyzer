<?php

namespace App\Console\Commands;

use App\Console\Concerns\ManagesPythonBackend;
use Illuminate\Foundation\Console\ServeCommand as BaseServeCommand;
use Symfony\Component\Process\Process;

class ServeCommand extends BaseServeCommand
{
    use ManagesPythonBackend;

    public function handle(): int
    {
        $this->line('');
        $this->line('  CaseAnalyzer — Forensic Image Analyzer');
        $this->line('  ─────────────────────────────────────');
        $this->line('');

        $backendProcess = $this->startPythonBackend();

        if ($backendProcess) {
            $backendUrl = config('forensic.backend_url', 'http://localhost:8001');
            $this->info("  [OK] Backend Python activo en {$backendUrl}");
        } else {
            $this->warn('  [WARN] Backend Python no pudo iniciarse. Revisa LeerDD/requirements.txt');
        }

        $this->line('');

        $exit = parent::handle();

        $backendProcess?->stop(3);

        return $exit;
    }

    protected function serverCommand(): array
    {
        $base = parent::serverCommand();

        $ini = [
            'post_max_size=0',
            'upload_max_filesize=0',
            'memory_limit=512M',
            'max_execution_time=0',
            'max_input_time=-1',
        ];

        $flags = [];
        foreach ($ini as $setting) {
            $flags[] = '-d';
            $flags[] = $setting;
        }

        return [$base[0], ...$flags, ...\array_slice($base, 1)];
    }

    private function startPythonBackend(): ?Process
    {
        $backendDir = base_path('LeerDD');

        if (! \is_dir($backendDir) || ! \file_exists("$backendDir/main.py")) {
            return null;
        }

        $python = $this->findPython();
        if (! $python) {
            return null;
        }

        $this->installDeps($python, $backendDir);
        $this->setupWslTools();

        $backendPort = (int) config('forensic.backend_port', 8001);

        $process = new Process(
            [
                $python, '-m', 'uvicorn', 'main:app',
                '--host', '0.0.0.0',
                '--port', (string) $backendPort,
                '--no-access-log',
                '--log-level', 'warning',
            ],
            $backendDir,
            null,
            null,
            null
        );

        $process->start();

        $attempts = 0;
        while ($attempts < 15) {
            \usleep(200_000);
            $attempts++;
            $conn = @\fsockopen('127.0.0.1', $backendPort, $errno, $errstr, 0.2);
            if ($conn) {
                \fclose($conn);
                break;
            }
        }

        return $process;
    }

    private function setupWslTools(): void
    {
        $marker = base_path('.wsl_tools_ready');
        if (\file_exists($marker)) {
            return;
        }

        $wsl = $this->findWsl();
        if (! $wsl) {
            return;
        }

        $check = new Process([$wsl, '--list', '--quiet']);
        $check->run();
        if (! $check->isSuccessful()) {
            $this->line('  [setup] Instalando WSL Ubuntu...');
            $install = new Process([$wsl, '--install', '-d', 'Ubuntu', '--no-launch']);
            $install->setTimeout(600);
            $install->run();
            \sleep(10);
        }

        $this->line('  [setup] Instalando sleuthkit y ewf-tools en WSL...');
        $apt = new Process(
            [$wsl, 'bash', '-c', 'sudo apt-get update -qq && sudo apt-get install -y -qq sleuthkit ewf-tools 2>/dev/null']
        );
        $apt->setTimeout(300);
        $apt->run();

        if ($apt->isSuccessful()) {
            $this->line('  [setup] Herramientas WSL listas.');
            \file_put_contents($marker, date('c'));
        } else {
            $this->warn('  [WARN] No se pudieron instalar herramientas WSL. Revisa los permisos de sudo.');
        }
    }

    private function findWsl(): ?string
    {
        $p = new Process(['where', 'wsl']);
        $p->run();
        if ($p->isSuccessful()) {
            return 'wsl';
        }
        $abs = (\getenv('SystemRoot') ?: 'C:\\Windows') . '\\System32\\wsl.exe';
        return \file_exists($abs) ? $abs : null;
    }
}
