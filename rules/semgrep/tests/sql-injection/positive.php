<?php
function find(PDO $db, string $id): array
{
    // ruleid: php-sql-string-concat
    $rows = $db->query("SELECT * FROM users WHERE id = " . $id);
    // ruleid: php-sql-string-concat
    $db->exec("DELETE FROM users WHERE id = $id");
    return $rows;
}

function laravel(string $id)
{
    // ruleid: laravel-raw-sql-non-literal
    DB::select("SELECT * FROM users WHERE id = " . $id);
    // ruleid: laravel-raw-sql-non-literal
    User::query()->whereRaw("id = " . $id)->get();
}
