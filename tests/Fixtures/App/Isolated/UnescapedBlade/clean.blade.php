<h1>{{ $title }}</h1>
<div>{!! $slot !!}</div>
<form>
    {!! csrf_field() !!}
    {!! method_field('PUT') !!}
    {!! '<br>' !!}
</form>
<p>@{!! $escapedByAt !!}</p>
