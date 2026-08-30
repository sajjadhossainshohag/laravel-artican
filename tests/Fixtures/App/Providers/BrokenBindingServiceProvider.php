<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Providers;

use Illuminate\Support\ServiceProvider;

class BrokenBindingServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->bind(
            \SajjadHossain\Artican\Tests\Fixtures\App\Contracts\PaymentGateway::class,
            \SajjadHossain\Artican\Tests\Fixtures\App\Services\DeletedPaymentGateway::class
        );
    }

    public function boot(): void
    {
        //
    }
}
