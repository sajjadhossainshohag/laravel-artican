<?php

namespace SajjadHossain\Artican\Tests\Feature\Checks\Queue;

use SajjadHossain\Artican\Tests\TestCase;
use SajjadHossain\Artican\Checks\Jobs\FailedJobTableMissingCheck;
use SajjadHossain\Artican\Enums\Severity;
use Illuminate\Support\Facades\Schema;

class FailedJobTableMissingCheckTest extends TestCase
{
    /** @test */
    public function it_detects_missing_failed_jobs_table(): void
    {
        Schema::dropIfExists('failed_jobs');

        $result = (new FailedJobTableMissingCheck())->run();

        $this->assertCheckFailed($result, Severity::Warning);
    }

    /** @test */
    public function it_passes_when_failed_jobs_table_exists(): void
    {
        Schema::dropIfExists('failed_jobs');
        Schema::create('failed_jobs', function ($table) {
            $table->id();
            $table->string('uuid')->unique();
            $table->text('connection');
            $table->text('queue');
            $table->longText('payload');
            $table->longText('exception');
            $table->timestamp('failed_at')->useCurrent();
        });

        $result = (new FailedJobTableMissingCheck())->run();

        $this->assertCheckPassed($result);

        Schema::dropIfExists('failed_jobs');
    }
}
