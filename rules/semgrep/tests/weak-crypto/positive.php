<?php
function digest(string $password): string
{
    // ruleid: php-weak-hash-algorithm
    $hash = md5($password);
    // ruleid: php-insecure-random-for-secret
    $token = mt_rand(0, 999999);
    return $hash . $token;
}
