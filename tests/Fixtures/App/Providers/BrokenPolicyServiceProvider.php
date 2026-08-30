<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Gate;

class BrokenPolicyServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Gate::policy(
            \SajjadHossain\Artican\Tests\Fixtures\App\Models\Good\WellDefinedModel::class,
            \SajjadHossain\Artican\Tests\Fixtures\App\Policies\NonExistentPolicy::class
        );
    }
}
