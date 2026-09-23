<?php
function load(string $blob)
{
    // ruleid: php-unsafe-unserialize
    return unserialize($blob);
}
