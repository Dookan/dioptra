<?php
function search(string $needle, string $haystack): bool
{
    // ok: php-regex-from-input
    return (bool) preg_match('/' . preg_quote($needle, '/') . '/', $haystack);
}
