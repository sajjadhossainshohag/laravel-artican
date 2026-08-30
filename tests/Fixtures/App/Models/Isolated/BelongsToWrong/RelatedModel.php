<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Models\Isolated\BelongsToWrong;

use Illuminate\Database\Eloquent\Model;

class BelongsToWrongParent extends Model
{
    protected $table = 'belongs_to_wrong_parents';
    protected $fillable = ['name'];
}