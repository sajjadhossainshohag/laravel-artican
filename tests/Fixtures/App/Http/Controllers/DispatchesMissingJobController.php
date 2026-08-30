<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Http\Controllers;

class DispatchesMissingJobController
{
    public function store(): void
    {
        \SajjadHossain\Artican\Tests\Fixtures\App\Jobs\NonExistentJob::dispatch();
    }

    public function update(): void
    {
        \SajjadHossain\Artican\Tests\Fixtures\App\Jobs\NonExistentJob::dispatchIf(true);
    }

    public function chain(): void
    {
        \Illuminate\Support\Facades\Bus::chain([
            new \SajjadHossain\Artican\Tests\Fixtures\App\Jobs\NonExistentJob(1),
            \SajjadHossain\Artican\Tests\Fixtures\App\Jobs\NonExistentJob::class,
        ])->dispatch();
    }
}
