<?php

namespace App\Domain\Pagos;

class Calculadora
{
    public function calcularMora(array $cuotas, int $diasGracia, string $regimen): float
    {
        $total = 0.0;

        foreach ($cuotas as $cuota) {
            $atraso = (int) ($cuota['dias'] ?? 0);
            if ($atraso <= $diasGracia) {
                continue;
            }

            $tasa = match ($regimen) {
                'preferencial' => 0.01,
                'ordinario' => 0.025,
                default => 0.05,
            };

            if ($atraso > 90) {
                $tasa = $tasa * 2;
            }

            $total += $cuota['monto'] * $tasa * $atraso;
        }

        if ($total < 0) {
            throw new \DomainException('mora negativa');
        }

        return round($total, 2);
    }
}
