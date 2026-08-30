<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Providers;

use Illuminate\Support\ServiceProvider;

class BrokenListenersProvider extends ServiceProvider
{
    protected $listen = [
        \SajjadHossain\Artican\Tests\Fixtures\App\Events\OrderShipped::class => [
            \SajjadHossain\Artican\Tests\Fixtures\App\Listeners\DeletedListener::class,
            \SajjadHossain\Artican\Tests\Fixtures\App\Listeners\SendShipmentNotification::class,
        ],
    ];

    public function boot(): void
    {
        \Illuminate\Support\Facades\Event::listen(
            \SajjadHossain\Artican\Tests\Fixtures\App\Listeners\NonExistentListener::class,
            'handle'
        );
    }
}
