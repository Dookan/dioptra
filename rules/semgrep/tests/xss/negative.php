<?php
function show(): void
{
    // ok: php-echo-request-data
    echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
}
