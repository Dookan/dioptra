<?php
class Usuario extends Model
{
    // ok: laravel-model-unguarded
    protected $fillable = ['nombre', 'correo'];
}

class UsuarioController
{
    public function store(Request $request)
    {
        // ok: laravel-mass-assignment-request-all
        return Usuario::create($request->only(['nombre', 'correo']));
    }
}
