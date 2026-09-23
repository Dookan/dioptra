<?php

namespace App\Http\Controllers;

class SolicitudController
{
    public function resolverEstado(string $accion, array $payload): string
    {
        try {
            switch ($accion) {
                case 'aprobar':
                    $estado = 'aprobada';
                    break;
                case 'rechazar':
                    $estado = 'rechazada';
                    break;
                case 'devolver':
                    $estado = empty($payload['motivo']) ? 'pendiente' : 'devuelta';
                    break;
                default:
                    throw new \InvalidArgumentException('accion desconocida');
            }
        } catch (\InvalidArgumentException $e) {
            return 'invalida';
        } catch (\RuntimeException $e) {
            return 'error';
        }

        return $estado;
    }
}
