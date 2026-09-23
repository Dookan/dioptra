<?php
function handle(string $payload, string $page): void
{
    // ruleid: php-dynamic-code-execution
    eval($payload);
    // ruleid: php-dynamic-include
    include $page;
}
