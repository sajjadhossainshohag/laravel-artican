<?php

namespace SajjadHossain\Artican\Output;

use Illuminate\Console\OutputStyle;
use SajjadHossain\Artican\DTOs\CheckResult;
use SajjadHossain\Artican\Enums\Severity;
use Symfony\Component\Console\Formatter\OutputFormatter;

class ConsoleRenderer
{
    /** Text safe to put inside console markup: "<...>" in names, paths and messages stays literal. */
    public static function escape(mixed $value): string
    {
        $text = is_scalar($value) || $value === null ? (string) $value : (string) json_encode($value, JSON_UNESCAPED_SLASHES);

        // Every "<" is escaped on its own. OutputFormatter::escape() on older Symfony versions consumes the
        // character before a "<", so the second "<" of "<<b>>" would stay live.
        return OutputFormatter::escapeTrailingBackslash(str_replace('<', '\\<', $text));
    }

    public function render(OutputStyle $output, array $results, float $duration = 0): void
    {
        $passed = 0;
        $errors = 0;
        $warnings = 0;
        $infos = 0;

        // Names, paths and messages can contain "<...>" (e.g. a file called "<x>.key"), which the console
        // would parse as a style tag, so every interpolated value is escaped.
        $e = static fn (mixed $value): string => self::escape($value);

        foreach ($results as $result) {
            $status = $result->passed ? '✓' : '✗';
            $color = $result->passed ? 'green' : ($result->severity->value === 'error' ? 'red' : 'yellow');

            $output->writeln("  <fg={$color}>{$status}</> {$e($result->check)}");
            $output->writeln("     {$e($result->message)}");

            foreach ($result->locations as $loc) {
                if (isset($loc['file'], $loc['line'], $loc['issue'], $loc['value'])) {
                    $output->writeln("     <fg=gray>  {$e($loc['file'])}:{$e($loc['line'])} — {$e($loc['issue'])}: `{$e($loc['value'])}`</>");
                } elseif (isset($loc['file'], $loc['line'])) {
                    $detail = isset($loc['issue']) ? ' — ' . $e($loc['issue']) : '';
                    $output->writeln("     <fg=gray>  {$e($loc['file'])}:{$e($loc['line'])}{$detail}</>");
                } elseif (isset($loc['file'])) {
                    $detail = isset($loc['issue']) ? ' — ' . $e($loc['issue']) : '';
                    $output->writeln("     <fg=gray>  {$e($loc['file'])}{$detail}</>");
                } else {
                    $output->writeln("     <fg=gray>  " . $e(json_encode($loc, JSON_UNESCAPED_SLASHES)) . "</>");
                }
            }

            if (!$result->passed && $result->suggestion) {
                $output->writeln("     <fg=blue>→ {$e($result->suggestion)}</>");
            }

            if ($result->passed) {
                $passed++;
            } elseif ($result->severity === Severity::Error) {
                $errors++;
            } elseif ($result->severity === Severity::Warning) {
                $warnings++;
            } else {
                $infos++;
            }
        }

        $parts = ["{$passed} passed"];
        if ($errors > 0) {
            $parts[] = "{$errors} errors";
        }
        if ($warnings > 0) {
            $parts[] = "{$warnings} warnings";
        }
        if ($infos > 0) {
            $parts[] = "{$infos} info";
        }

        $output->newLine();
        $output->writeln('  Results: ' . implode(', ', $parts) . ($duration > 0 ? ' (' . number_format($duration / 1000, 2) . 's)' : ''));
    }
}
