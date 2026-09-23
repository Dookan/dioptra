<?php
function find(PDO $db, string $id): array
{
    // ok: php-sql-string-concat
    $stmt = $db->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$id]);
    return $stmt->fetchAll();
}

function laravel(string $id)
{
    // ok: laravel-raw-sql-non-literal
    User::query()->whereRaw('id = ?', [$id])->get();
}
