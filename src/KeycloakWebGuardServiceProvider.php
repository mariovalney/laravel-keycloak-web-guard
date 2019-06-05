<?php

namespace Vizir\KeycloakWebGuard;

use Auth;
use Illuminate\Support\ServiceProvider;
use Vizir\KeycloakWebGuard\Auth\Guard\KeycloakWebGuard;

class KeycloakWebGuardServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        // Configuration
        $config = __DIR__ . '/../config/keycloak-web.php';

        $this->publishes([$config => config_path('keycloak-web.php')], 'config');
        $this->mergeConfigFrom($config, 'keycloak-web');

        // Routes
        require_once __DIR__ . '/../routes/keycloak-web.php';
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        // Keycloak Web Guard
        Auth::extend('keycloak-web', function ($app, $name, array $config) {
            return new KeycloakWebGuard($app->request);
        });
    }
}
