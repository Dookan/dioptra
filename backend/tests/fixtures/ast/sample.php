<?php

namespace App\Sample;

class Account
{
    public function check(int $age, ?string $name = null): string
    {
        if ($age >= 18 && $name !== null) {
            $label = 'adult';
        } elseif ($age < 0) {
            throw new \InvalidArgumentException('negative');
        } else {
            $label = 'minor';
        }

        $total = 0;
        foreach (range(0, $age) as $i) {
            $total += $i;
        }

        while ($total > 100) {
            $total -= 10;
        }

        try {
            $label .= $this->suffix($total);
        } catch (\RuntimeException $e) {
            return 'error';
        } finally {
            $total = $total ?? 0;
        }

        return $total > 50 ? $label : 'small';
    }

    private function suffix(int $total): string
    {
        switch ($total) {
            case 0:
                return 'zero';
            default:
                return 'some';
        }
    }
}
