<?php

namespace App\Support;

final class Documento
{
    public static function validarCedula(?string $cedula, string $nacionalidad): bool
    {
        if ($cedula === null || $cedula === '') {
            return false;
        }

        $limpia = preg_replace('/[^0-9]/', '', $cedula);
        if (strlen($limpia) < 6 || strlen($limpia) > 8) {
            return false;
        }

        if ($nacionalidad !== 'V' && $nacionalidad !== 'E') {
            return false;
        }

        return (int) $limpia > 0;
    }
}
