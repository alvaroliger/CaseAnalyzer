<?php

return [
    /*
    | URL del backend Python (FastAPI / LeerDD).
    | Override: FORENSIC_BACKEND_URL en .env
    */
    'backend_url' => env('FORENSIC_BACKEND_URL', 'http://127.0.0.1:8001'),

    /*
    | Timeout en segundos para la conexión HTTP de Laravel al backend Python.
    | El backend Python tiene su propio timeout (ANALYSIS_TIMEOUT, por defecto 7200 s).
    | Este valor debe ser mayor que ANALYSIS_TIMEOUT para no cortar antes.
    */
    'timeout' => env('FORENSIC_TIMEOUT', 7260),

    /*
    | Puerto en el que arranca el backend Python cuando se usa `php artisan serve`.
    */
    'backend_port' => env('FORENSIC_BACKEND_PORT', 8001),

    /*
    | Extensiones de imagen forense aceptadas.
    */
    'allowed_extensions' => ['dd', 'img', 'raw', 'iso', 'e01', '001', 'bin'],

    /*
    | Número máximo de ficheros devueltos en el listado del filesystem.
    | Override: MAX_FILES en el entorno Python (variable de entorno).
    */
    'max_files' => env('FORENSIC_MAX_FILES', 5000),
];
