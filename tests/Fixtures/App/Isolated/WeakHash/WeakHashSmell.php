<?php

namespace Fixtures\WeakHash;

class WeakHashSmell
{
    public function weak($user, $request, $plain, $secret, $x, $token)
    {
        $user->password = md5($request->input('pw'));                    // 1
        $row = ['password' => sha1($plain)];                             // 2
        $apiToken = md5(uniqid());                                       // 3
        $hash = md5($user->password);                                    // 4
        $h = sha1($request->input('api_key') . 'salt');                  // 5
        $check = hash('md5', $secret);                                   // 6
        $user->remember_token = \sha1(time());                           // 7
        $data['userPassword'] = md5($x);                                 // 8
        $token = md5($token);                                            // 9
        $legacy = hash('SHA1', $user->getPassword());                    // 10
        $token = md5(uniqid()) . 'x';                                    // 11
        $token = strtoupper(sha1(time()));                               // 12
        $csrf = md5(csrf_token());                                       // 13
        $appKey = md5(config('app.key'));                                // 14
        $tokens[] = md5(uniqid());                                       // 15
        $secret .= sha1(microtime());                                    // 16
        $APIToken = md5(uniqid());                                       // 21
        $viaHelper = md5(request('password'));                           // 22
        $checked = Hash::check(md5($request->input('password')), $stored); // 23
        $user->password_reset = md5(Str::random());                      // 24
        $secret_code = sha1(microtime());                                // 25
        $apiKeyHex = md5(uniqid());                                      // 26
        $secretKey = md5(uniqid());                                      // 27
        $named = hash(algo: 'md5', data: $user->password);               // 28
        if (md5($input) === $user->password) {}                          // 29
        if (hash_equals($user->api_token, sha1($raw))) {}                // 30
        $found = User::where('password', md5($input))->first();          // 31
        $key = $user->tokens()->where('token', sha1($raw))->first();     // 32
        $fromArray = md5($tokens['a']);                                  // 33
        $hashed = array_map('md5', $passwords);                          // 34
        $pass = md5(uniqid());                                           // 35
        // Crypt is reversible encryption, not a strong hash, so it does not excuse the md5 inside:
        $encrypted = Crypt::encrypt(md5($user->password));               // 19
        // Nested weak hashes on one line are one finding, not two:
        $double = md5(md5($user->password));                             // 17
        $pair = [md5($user->password), sha1($user->password)];           // 18, 18
    }
}
