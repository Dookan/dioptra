<?php
function go(string $next): void
{
    // ok: php-open-redirect
    $allowed = ['/inicio', '/perfil'];
    header('Location: ' . (in_array($next, $allowed, true) ? $next : '/inicio'));
}
