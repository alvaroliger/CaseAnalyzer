<?php

namespace app\Console;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;

class Kernel extends ConsoleKernel
{
    /**
     * Registrar comandos personalizados, incluyendo el ServeCommand
     * que arranca el backend Python automáticamente.
     */
    protected $commands = [
        Commands\ServeCommand::class,
        Commands\BackendCommand::class,
    ];

    protected function schedule(Schedule $schedule): void
    {
        // Limpieza automática de archivos temporales del backend cada hora
        $schedule->command('backend:cleanup')->hourly();
    }

    protected function commands(): void
    {
        $this->load(__DIR__ . '/Commands');
        require base_path('routes/console.php');
    }
}