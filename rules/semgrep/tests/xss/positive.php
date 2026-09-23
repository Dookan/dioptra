<?php
function show(): void
{
    // ruleid: php-echo-request-data
    echo $_GET['name'];
    // ruleid: php-echo-request-data
    echo $_POST['comment'];
}
