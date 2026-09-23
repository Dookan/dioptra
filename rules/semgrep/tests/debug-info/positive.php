<?php
function inspect(array $payload): void
{
    // ruleid: php-debug-output-function
    var_dump($payload);
    // ruleid: php-display-errors-enabled
    ini_set('display_errors', '1');
}
