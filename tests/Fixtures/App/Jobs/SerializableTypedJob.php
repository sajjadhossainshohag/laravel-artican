<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Jobs;

use Illuminate\Contracts\Queue\ShouldQueue;

class SerializableTypedJob implements ShouldQueue
{
    public function __construct(
        public int $userId,
        public array $tags = [],
        public string $action = 'process',
    ) {}

    public function handle(): void {}
}