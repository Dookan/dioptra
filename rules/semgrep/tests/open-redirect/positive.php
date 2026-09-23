<?php
function go(): void
{
    // ruleid: php-open-redirect
    header('Location: ' . $_GET['next']);
}
