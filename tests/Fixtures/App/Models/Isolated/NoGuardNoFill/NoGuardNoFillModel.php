<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Models\Broken;

use Illuminate\Database\Eloquent\Model;

/**
 * Pure broken case: extends Model and declares neither $fillable nor
 * $guarded. The check should flag this.
 */
class NoGuardNoFillModel extends Model
{
    protected $table = 'no_guard_no_fill_models';
}