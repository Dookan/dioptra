<?php
function handle(string $page): void
{
    // ok: php-dynamic-code-execution
    $allowed = ['home' => 'home.php'];
    // ok: php-dynamic-include
    include __DIR__ . '/views/home.php';
}
