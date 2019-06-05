<?php

namespace Vizir\KeycloakWebGuard\Exceptions;

class KeycloakCallbackException extends \RuntimeException
{
    /**
     * Keycloak Callback Error
     *
     * @param string|null     $message  [description]
     * @param \Throwable|null $previous [description]
     * @param array           $headers  [description]
     * @param int|integer     $code     [description]
     */
    public function __construct(string $error = '')
    {
        $message = '[Keycloak Error] ' . $error;

        parent::__construct($message);
    }
}
