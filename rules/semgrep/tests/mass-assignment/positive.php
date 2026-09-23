<?php
class Usuario extends Model
{
    // ruleid: laravel-model-unguarded
    protected $guarded = [];
}

class UsuarioController
{
    public function store(Request $request)
    {
        // ruleid: laravel-mass-assignment-request-all
        return Usuario::create($request->all());
    }
}
