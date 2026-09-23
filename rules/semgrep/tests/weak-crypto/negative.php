<?php
function digest(string $password): string
{
    // ok: php-weak-hash-algorithm
    $hash = password_hash($password, PASSWORD_ARGON2ID);
    // ok: php-insecure-random-for-secret
    $token = bin2hex(random_bytes(16));
    return $hash . $token;
}
