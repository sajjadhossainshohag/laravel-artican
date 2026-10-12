<?php

namespace SajjadHossain\Artican\Tests\Unit\Checks\Security;

use SajjadHossain\Artican\Checks\Security\FileUploadWithoutValidationCheck;
use SajjadHossain\Artican\Enums\Severity;
use SajjadHossain\Artican\Tests\TestCase;

class FileUploadWithoutValidationCheckTest extends TestCase
{
    private string $fixturePath;

    protected function setUp(): void
    {
        parent::setUp();
        $this->fixturePath = __DIR__ . '/../../../Fixtures/App/Isolated/FileUpload';
    }

    /** @test */
    public function it_detects_every_unvalidated_upload_write(): void
    {
        $result = (new FileUploadWithoutValidationCheck())
            ->withPaths([$this->fixturePath . '/FileUploadSmell.php'])
            ->run();

        $this->assertCheckFailed($result, Severity::Warning, 'without validation');
        $this->assertCount(52, $result->locations);
    }

    /** @test */
    public function it_reports_the_line_of_each_write(): void
    {
        $result = (new FileUploadWithoutValidationCheck())
            ->withPaths([$this->fixturePath . '/FileUploadSmell.php'])
            ->run();

        $expected = [];
        foreach (file($this->fixturePath . '/FileUploadSmell.php') as $index => $line) {
            // "// 7" marks one write on that line; "// 38, 38" marks two separate writes on it.
            if (preg_match('#// (\d+(?:, \d+)*)$#', rtrim($line), $match)) {
                for ($i = 0, $count = count(explode(',', $match[1])); $i < $count; $i++) {
                    $expected[] = $index + 1;
                }
            }
        }

        $actual = array_column($result->locations, 'line');
        sort($actual);

        $this->assertSame($expected, $actual);
    }

    /** @test */
    public function it_passes_when_the_upload_is_validated_or_not_an_upload(): void
    {
        $result = (new FileUploadWithoutValidationCheck())
            ->withPaths([$this->fixturePath . '/FileUploadClean.php'])
            ->run();

        $this->assertCheckPassed($result);
    }

    /** @test */
    public function it_only_reports_the_smell_file_when_both_are_scanned(): void
    {
        $result = (new FileUploadWithoutValidationCheck())
            ->withPaths([$this->fixturePath])
            ->run();

        $this->assertCount(52, $result->locations);
        foreach ($result->locations as $location) {
            $this->assertStringContainsString('FileUploadSmell.php', $location['file']);
        }
    }

    /** @test */
    public function overlapping_scan_paths_do_not_double_report(): void
    {
        $result = (new FileUploadWithoutValidationCheck())
            ->withPaths([$this->fixturePath, $this->fixturePath . '/FileUploadSmell.php', $this->fixturePath])
            ->run();

        $this->assertCount(52, $result->locations);
    }

    /** @test */
    public function a_bare_global_alias_import_of_the_storage_facade_is_recognised(): void
    {
        $result = (new FileUploadWithoutValidationCheck())
            ->withPaths([__DIR__ . '/../../../Fixtures/App/Isolated/FileUploadAlias/BareImport.php'])
            ->run();

        $this->assertCheckFailed($result, Severity::Warning);
        $this->assertCount(1, $result->locations);
    }

    /** @test */
    public function it_has_the_expected_metadata(): void
    {
        $check = new FileUploadWithoutValidationCheck();

        $this->assertSame('security', $check->category());
        $this->assertSame(Severity::Warning, $check->severity());
    }
}
