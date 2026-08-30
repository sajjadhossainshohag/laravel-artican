<?php

namespace SajjadHossain\Artican\Tests\Fixtures\App\Models\Isolated\HasManyWrong;

use Illuminate\Database\Eloquent\Model;

class HasManyWrongRelated extends Model
{
    protected $table = 'has_many_wrong_related';
    protected $fillable = ['name'];
}