<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Models\Good;

use Illuminate\Database\Eloquent\Model;

/**
 * Tests that `public $fillable = [...]` is recognized (not just `protected`).
 */
class PublicFillableModel extends Model
{
    protected $table = 'public_fillable_models';
    public $fillable = ['name'];
}