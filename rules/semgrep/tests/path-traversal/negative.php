<?php
function download(string $name): void
{
    // ok: php-path-traversal
    $base = realpath('/srv/uploads');
    $path = realpath($base . '/' . basename($name));
    if ($path !== false && str_starts_with($path, $base . '/')) {
        readfile($path);
    }
}
