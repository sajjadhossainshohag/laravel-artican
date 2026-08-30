<?php

namespace SajjadHossain\Artican\Commands;

use Illuminate\Console\Command;
use SajjadHossain\Artican\CheckRegistry;

class WorkerCommand extends Command
{
    protected $signature = 'artican:worker
        {--only= : Comma-separated categories to run}
        {--output= : Path to write serialized results}';

    protected $description = '[Internal] Run a subset of artican checks for parallel execution';

    public function handle(CheckRegistry $registry): int
    {
        $checkClasses = $registry->all();
        $only = $this->option('only');
        $outputPath = $this->option('output');

        $instances = [];
        foreach ($checkClasses as $class) {
            $instances[] = new $class();
        }

        if ($only) {
            $categories = explode(',', $only);
            $instances = array_values(array_filter($instances, fn ($c) => in_array($c->category(), $categories, true)));
        }

        $results = [];
        foreach ($instances as $check) {
            $results[] = $check->run();
        }

        if ($outputPath) {
            file_put_contents($outputPath, serialize($results));
        }

        return 0;
    }
}
