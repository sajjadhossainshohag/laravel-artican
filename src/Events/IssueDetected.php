<?php

namespace SajjadHossain\Artican\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use SajjadHossain\Artican\DTOs\CheckResult;

class IssueDetected
{
    use Dispatchable, InteractsWithSockets;

    public function __construct(
        public readonly CheckResult $result,
    ) {}
}
