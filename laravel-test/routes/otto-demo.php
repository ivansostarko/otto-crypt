<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\OttoDemoController;

Route::get('/otto-demo', [OttoDemoController::class, 'index'])->name('otto.demo');

// Text endpoints
Route::post('/otto-demo/text/encrypt', [OttoDemoController::class, 'encryptText'])->name('otto.text.encrypt');
Route::post('/otto-demo/text/decrypt', [OttoDemoController::class, 'decryptText'])->name('otto.text.decrypt');

// File endpoints (generic: photos, docs, audio, video)
Route::post('/otto-demo/file/encrypt', [OttoDemoController::class, 'encryptFile'])->name('otto.file.encrypt');
Route::post('/otto-demo/file/decrypt', [OttoDemoController::class, 'decryptFile'])->name('otto.file.decrypt');
