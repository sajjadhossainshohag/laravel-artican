<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Console;

class BrokenSchedule
{
    public function schedule($schedule): void
    {
        $schedule->command(\SajjadHossain\Artican\Tests\Fixtures\App\Console\NonExistentCommand::class)->daily();
    }
}
