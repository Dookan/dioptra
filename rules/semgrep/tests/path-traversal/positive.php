<?php
function download(): void
{
    // ruleid: php-path-traversal
    readfile($_GET['file']);
    // ruleid: php-path-traversal
    $data = file_get_contents('/srv/uploads/' . $_POST['name']);
}
