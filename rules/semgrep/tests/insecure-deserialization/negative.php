<?php
function load(string $blob)
{
    // ok: php-unsafe-unserialize
    return unserialize($blob, ['allowed_classes' => false]);
}
