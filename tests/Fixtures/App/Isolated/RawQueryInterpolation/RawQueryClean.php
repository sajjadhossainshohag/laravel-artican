<?php

namespace Fixtures\RawQueryInterpolation;

use Illuminate\Support\Facades\DB;

class RawQueryClean
{
    public function bindings($query, $price)
    {
        $query->whereRaw('price > ?', [$price]);
        $query->whereRaw('price > :price', ['price' => $price]);
    }

    public function literal($query)
    {
        $query->selectRaw('count(*) as total');
        $query->orderByRaw('created_at desc');
        return DB::raw('now()');
    }

    public function constantsAndCasts($query, $id)
    {
        $query->whereRaw('id = ' . (int) $id);
        $query->whereRaw('id = 1' . self::SUFFIX);
        $query->whereRaw('id = ' . PHP_INT_MAX);
        $query->whereRaw(sprintf('id = %d', intval($id)));
    }

    public function placeholderLists($query, array $ids, $id, $n)
    {
        $query->whereRaw('id in (' . implode(',', array_fill(0, count($ids), '?')) . ')', $ids);
        $query->whereRaw('id in (' . str_repeat('?,', $n - 1) . '?)', $ids);
        $query->whereRaw(sprintf('id = %d', $id));
        $query->whereRaw(sprintf('id = %2$d and parent = %1$d', $id, $id));
        $query->whereRaw('id < ' . count($ids));
        DB::connection('reports')->select('select * from t where id = ?', [$id]);
    }

    public function prebuilt($query, string $sql)
    {
        // A bare variable may be a safe, prebuilt string.
        $query->whereRaw($sql);
    }

    public function notRawMethods($collection, $user)
    {
        $collection->raw("value $user");           // not DB::raw
        $user->select("column $user");             // instance select
        DB::table('users')->where('id', $user);
        DB::select('select * from users where id = ?', [$user]);
    }

    public function ternaryLiterals($query, $flag, $a, $b)
    {
        // Bare variables are not flagged, with or without a ternary around them.
        $query->orderByRaw($flag ? $a : $b);
        $query->orderByRaw($flag ? 'id asc' : 'id desc');
    }

    private const SUFFIX = ' and 1 = 1';
}
