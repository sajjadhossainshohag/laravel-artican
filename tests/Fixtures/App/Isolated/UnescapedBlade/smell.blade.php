<h1>{!! $title !!}</h1>
<div>{!! $post->body !!}</div>
{{-- {!! $commented !!} --}}
@verbatim
    {!! $verbatim !!}
@endverbatim
<p>{!!
    $multiLine
!!}</p>
<p>{!! e($x) . $y !!}</p>
<p>{!! "Hello $name" !!}</p>
