<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Models\Good;

use Illuminate\Database\Eloquent\Model;

/**
 * Tests that a typed property (`public array $fillable = [...]`) is recognized.
 */
class TypedFillableModel extends Model
{
    protected $table = 'typed_fillable_models';
    public array $fillable = ['name'];
}