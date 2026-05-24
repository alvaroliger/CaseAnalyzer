<?php

namespace App\Console\Concerns;

use Symfony\Component\Process\Process;

trait ManagesPythonBackend
{
    protected function findPython(): ?string
    {
        foreach (['python3', 'python', 'py'] as $candidate) {
            $p = new Process([$candidate, '--version']);
            $p->run();
            if ($p->isSuccessful()) {
                return $candidate;
            }
        }
        return null;
    }

    protected function installDeps(string $python, string $dir): void
    {
        $req = $dir . \DIRECTORY_SEPARATOR . 'requirements.txt';
        if (! \file_exists($req)) {
            return;
        }

        $proc = new Process([$python, '-m', 'pip', 'install', '-r', 'requirements.txt', '-q'], $dir);
        $proc->setTimeout(120);
        $proc->run();

        // pytsk3: solo instalar si hay wheel precompilado
        $check = new Process([$python, '-c', 'import pytsk3'], $dir);
        $check->run();
        if (! $check->isSuccessful()) {
            $pt = new Process(
                [$python, '-m', 'pip', 'install', 'pytsk3', '--only-binary', ':all:', '-q'],
                $dir
            );
            $pt->setTimeout(60);
            $pt->run();
        }
    }
}
