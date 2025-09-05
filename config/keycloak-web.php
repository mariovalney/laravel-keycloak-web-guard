<?php

return [
    /**
     * Keycloak Url
     *
     * Generally https://your-server.com/auth
     */
    'base_url' => env('KEYCLOAK_BASE_URL', ''),

    /**
     * Keycloak Realm
     *
     * Default is master
     */
    'realm' => env('KEYCLOAK_REALM', 'master'),

    /**
     * The Keycloak Server realm public key (string).
     *
     * @see Keycloak >> Realm Settings >> Keys >> RS256 >> Public Key
     */
    'realm_public_key' => env('KEYCLOAK_REALM_PUBLIC_KEY', null),

    /**
     * Keycloak Client ID
     *
     * @see Keycloak >> Clients >> Installation
     */
    'client_id' => env('KEYCLOAK_CLIENT_ID', null),

    /**
     * Keycloak Client Secret
     *
     * @see Keycloak >> Clients >> Installation
     */
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET', null),

    /**
     * We can cache the OpenId Configuration
     * The result from /realms/{realm-name}/.well-known/openid-configuration
     *
     * @link https://www.keycloak.org/docs/3.2/securing_apps/topics/oidc/oidc-generic.html
     */
    'cache_openid' => env('KEYCLOAK_CACHE_OPENID', false),

    /**
     * OpenID Configuration Source
     * 
     * Options:
     * - 'remote': Fetch from the public .well-known endpoint (default, less secure)
     * - 'local': Load from a local file path
     * - 'base64': Load from base64 encoded configuration in env/config
     */
    'openid_source' => env('KEYCLOAK_OPENID_SOURCE', 'remote'),

    /**
     * Local OpenID Configuration File Path
     * 
     * Used when openid_source is 'local'
     * Path to a local JSON file containing the OpenID configuration
     */
    'openid_local_path' => env('KEYCLOAK_OPENID_LOCAL_PATH', storage_path('app/keycloak/openid-configuration.json')),

    /**
     * Base64 Encoded OpenID Configuration
     * 
     * Used when openid_source is 'base64'
     * Base64 encoded JSON string of the OpenID configuration
     */
    'openid_base64_config' => env('KEYCLOAK_OPENID_BASE64_CONFIG', null),

    /**
     * Page to redirect after callback if there's no "intent"
     *
     * @see Vizir\KeycloakWebGuard\Controllers\AuthController::callback()
     */
    'redirect_url' => env('KEYCLOAK_REDIRECT_URL', '/admin'),

    /**
     * The routes for authenticate
     *
     * Accept a string as the first parameter of route() or false to disable the route.
     *
     * The routes will receive the name "keycloak.{route}" and login/callback are required.
     * So, if you make it false, you shoul register a named 'keycloak.login' route and extend
     * the Vizir\KeycloakWebGuard\Controllers\AuthController controller.
     */
    'routes' => [
        'login' => 'login',
        'logout' => 'logout',
        'register' => 'register',
        'callback' => 'callback',
    ],

    /**
    * GuzzleHttp Client options
    *
    * @link http://docs.guzzlephp.org/en/stable/request-options.html
    */
   'guzzle_options' => [],

    /**
     * Keycloak optional scopes
     *
     * array of strings
     */
    'scopes' => [],
];
