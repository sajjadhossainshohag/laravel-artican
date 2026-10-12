<?php

namespace Fixtures\RawQueryInterpolation;

use Illuminate\Support\Facades\DB;

class RawQuerySmell
{
    public function interpolated($query, $price)
    {
        $query->whereRaw("price > $price");                          // 1
    }

    public function braces($query, $user)
    {
        $query->whereRaw("name = '{$user->name}'");                  // 2
    }

    public function concatenated($query, $column)
    {
        $query->orderByRaw('created_at ' . $column);                 // 3
    }

    public function selectRaw($query, $alias)
    {
        return $query->selectRaw("count(*) as {$alias}");            // 4
    }

    public function facade($id)
    {
        return DB::select('select * from users where id = ' . $id);  // 5
    }

    public function raw($term)
    {
        return DB::raw("lower(name) like '%$term%'");                // 6
    }

    public function formatted($query, $id)
    {
        $query->whereRaw(sprintf('id = %s', $id));                   // 7
    }

    public function ternary($query, $dir)
    {
        $query->orderByRaw($dir ? "id $dir" : 'id');                 // 8
    }

    public function statement($table)
    {
        DB::statement("drop table $table");                          // 9
    }

    public function staticModel($column)
    {
        return \App\Models\User::havingRaw("sum($column) > 1");      // 10
    }

    public function fromRaw($query, $table)
    {
        return $query->fromRaw("$table as t");                       // 11
    }

    public function connection($id)
    {
        return DB::connection('reports')->select("select * from t where id = $id"); // 12
    }

    public function mixedFormat($query, $id, $name)
    {
        $query->whereRaw(sprintf("id = %d and name = '%s'", $id, $name)); // 13
    }
}
