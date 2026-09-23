<?php
function search(string $needle, string $haystack): bool
{
    // ruleid: php-regex-from-input
    return (bool) preg_match('/' . $needle . '/', $haystack);
}
