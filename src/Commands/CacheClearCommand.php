<?php

namespace SajjadHossain\Artican\Commands;

use Illuminate\Console\Command;
use SajjadHossain\Artican\ScanResultCache;

class CacheClearCommand extends Command
{
    protected $signature = 'artican:cache:clear';

    protected $description = 'Clear cached scan results';

    public function handle(ScanResultCache $cache): int
    {
        $cache->flush();
        $this->info('Artican scan cache cleared.');

        return 0;
    }
}
