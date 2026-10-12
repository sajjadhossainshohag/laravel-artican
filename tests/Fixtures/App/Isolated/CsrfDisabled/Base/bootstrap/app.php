<?php

use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function ($middleware) {
        $middleware->validateCsrfTokens(except: ['*']);
    })
    ->create();
