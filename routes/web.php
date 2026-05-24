<?php

use App\Http\Controllers\CaseController;
use Illuminate\Support\Facades\Route;

Route::get('/', [CaseController::class, 'index'])->name('home');

Route::prefix('api')->group(function () {
    Route::get('/health',                          [CaseController::class, 'health'])->middleware('throttle:60,1');
    Route::post('/analyze',                        [CaseController::class, 'analyze'])->middleware('throttle:10,1');
    Route::get('/file/{fileId}/{inode}',           [CaseController::class, 'fileContent'])->middleware('throttle:120,1');
    Route::get('/metadata/{fileId}/{inode}',       [CaseController::class, 'metadata'])->middleware('throttle:120,1');
    Route::delete('/cleanup/{fileId}',             [CaseController::class, 'cleanup'])->middleware('throttle:60,1');
    Route::get('/logs/{fileId}',                    [CaseController::class, 'analysisLog'])->middleware('throttle:60,1');
});
