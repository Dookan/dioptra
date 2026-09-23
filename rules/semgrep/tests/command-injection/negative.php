<?php
function run(string $name): void
{
    // ok: php-shell-command-injection
    system('convert /srv/fixed.png');
    // ok: php-shell-command-injection
    exec('ls -la');
}
