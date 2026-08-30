<?php

namespace SajjadHossain\Artican;

use Illuminate\Support\Facades\Cache;

class ScanResultCache
{
    public function remember(string $category, callable $callback): array
    {
        if (!config('artican.cache.enabled', true)) {
            return $callback();
        }

        $key = $this->key($category);
        $ttl = config('artican.cache.ttl', 3600);
        $store = config('artican.cache.store', 'file');

        return Cache::store($store)->remember($key, $ttl, $callback);
    }

    public function forget(string $category): void
    {
        Cache::forget($this->key($category));
    }

    public function flush(): void
    {
        $store = config('artican.cache.store', 'file');
        Cache::store($store)->flush();
    }

    private function key(string $category): string
    {
        return "artican_scan_{$category}";
    }
}
