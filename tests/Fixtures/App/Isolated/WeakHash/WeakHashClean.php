<?php

namespace Fixtures\WeakHash;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Hash as Hasher;

class WeakHashClean
{
    public function fine($user, $request, $content, $url, $path, $password, $name, $bypass, $passport)
    {
        // Non-security uses of md5/sha1 are fine.
        $etag = md5($content);
        $cacheKey = sha1($user->id . ':profile');
        $name = md5($name);
        $fingerprint = md5_file($path);
        $row = ['name' => md5($name), 'slug' => sha1($url)];

        // Strong algorithms and password hashers.
        $a = hash('sha256', $password);
        $b = hash('xxh3', $password);
        $c = Hash::make($password);
        $d = password_hash($password, PASSWORD_BCRYPT);
        $user->password = Hash::make($request->input('pw'));
        $user->remember_token = bin2hex(random_bytes(30));

        // Wrapped weak hashes are fine when the target and inputs are not secrets.
        $slug = strtoupper(md5(uniqid()) . 'x');
        $label = md5($content) . sha1($url);

        // A weak hash wrapped by a strong one is not what gets stored; names that only mention a token are not tokens.
        $user->password = Hash::make(md5($request->input('pw')));
        $user->password = Hash::make(md5($request->input('password')));
        $stored = bcrypt(sha1($user->password));
        $peppered = bcrypt(md5($user->password) . $pepper);
        $viaDriver = Hash::driver('bcrypt')->make(md5($request->input('password')));
        $viaHelper = app('hash')->make(md5($request->input('password')));
        $viaAlias = Hasher::make(md5($request->input('password')));
        $viaInjected = $this->hasher->make(md5($request->input('password')));

        // Only the leaf names the hashed value: an email reached through a token object is still an email.
        $emailKey = md5($user->token->email);
        $resetKey = md5($passwordReset->user->email);

        // "pass" inside a longer word or phrase is not a password: passThrough, pass_list, pass_number.
        $a = md5($passThrough);
        $b = sha1($pass_list);
        $passNumber = md5($url);
        $mapped = array_map('md5', $names);

        // A secret-looking label on a cache or log call is only a label.
        Cache::put('token', md5($payload), 60);
        $this->logger->info('password reset', ['id' => md5($email)]);

        // Looking up by a non-secret column, or caching under a plain key, is not a credential lookup.
        $byEmail = User::where('email', md5($input))->first();
        $cache->put('profile', md5($input));

        // Comparing two plain fingerprints is not a credential check.
        $same = md5($a) === md5($b);
        $fresh = md5($content) === $etag;
        $equal = hash_equals($etag, sha1($content));
        $tokenHasher = md5(...);
        $secretHash = sha1(...);
        $viaTernary = Hash::make($flag ? md5($user->password) : $other);
        $viaAnyCase = hash::make(md5($user->password));
        $nested = Hash::make(strtolower(sha1($user->password)));

        // A map keyed by a variable is not a password field.
        $lookup = [$password => md5($row), $tokenName => sha1($payload)];
        $hashed = password_hash(md5($password), PASSWORD_BCRYPT);
        $cacheTokenKey = md5($url);
        $tokenId = md5($url);
        $etag = md5($user->token_id . $request->input('password_url'));
        $passwordCount = md5($url);
        $secretLabel = sha1($url);
        $tokenCount = md5($url);

        // Hashing a derived value (a serialized or encoded structure) is a fingerprint, not a stored secret.
        $fp1 = md5(json_encode($tokens));
        $fp2 = md5(serialize($passwordRules));

        // A translated label is not a secret just because its text says "Password".
        $labelKey = md5(__('Password reset'));
        $cache = sha1(trans('auth.password'));

        // Names that merely contain "pass" are not passwords.
        $e = md5($bypass);
        $f = sha1($passport);

        // A method literally named md5 is not the function.
        $g = $this->md5($password);
    }

    private function md5(string $value): string
    {
        return $value;
    }
}
