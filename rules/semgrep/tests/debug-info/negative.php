<?php
function inspect(array $payload, LoggerInterface $log): void
{
    // ok: php-debug-output-function
    $log->debug('payload', $payload);
    // ok: php-display-errors-enabled
    ini_set('display_errors', '0');
}
