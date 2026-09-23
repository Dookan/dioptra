<?php
function run(string $name): void
{
    // ruleid: php-shell-command-injection
    system("convert " . $name);
    // ruleid: php-shell-command-injection
    shell_exec("ls $name");
}
