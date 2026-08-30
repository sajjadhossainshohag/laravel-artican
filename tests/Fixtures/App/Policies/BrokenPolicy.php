<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Policies;

class BrokenPolicy
{
    public function view(): bool
    {
        return false;
    }
}
