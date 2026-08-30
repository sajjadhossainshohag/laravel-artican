<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Middleware;

class RiskyTerminateMiddleware
{
    public function handle($request, $next)
    {
        return $next($request);
    }

    public function terminate($request, $response): void
    {
        \Log::info('Request completed');
        \Cache::put('last-request', now());
    }
}
