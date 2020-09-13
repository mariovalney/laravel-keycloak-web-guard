<?php

namespace Vizir\KeycloakWebGuard\Auth;

use Exception;

class KeycloakAccessToken
{
    /**
     * @var string
     */
    protected $accessToken;

    /**
     * @var string
     */
    protected $refreshToken;

    /**
     * @var string
     */
    protected $idToken;

    /**
     * @var int
     */
    protected $expires;

    /**
     * Constructs an access token.
     *
     * @param array $data The token from Keycloak as array.
     */
    public function __construct($data = [])
    {
        $data = (array) $data;

        if (! empty($data['access_token'])) {
            $this->accessToken = $data['access_token'];
        }

        if (! empty($data['refresh_token'])) {
            $this->refreshToken = $data['refresh_token'];
        }

        if (! empty($data['id_token'])) {
            $this->idToken = $data['id_token'];
        }

        if (! empty($data['expires_in'])) {
            $this->expires = (int) $data['expires_in'];
        }
    }

    /**
     * Get AccessToken
     *
     * @return string
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Get RefreshToken
     *
     * @return string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Get IdToken
     *
     * @return string
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * Check access token has expired
     *
     * @return boolean
     */
    public function hasExpired()
    {
        $exp = $this->parseAccessToken();
        $exp = $exp['exp'] ?? '';

        return time() < (int) $exp;
    }

    /**
     * Check the ID Token
     *
     * @throws Exception
     * @return void
     */
    public function validateIdToken($claims)
    {
        $token = $this->parseIdToken();
        if (empty($token)) {
            throw new Exception('ID Token is invalid.');
        }

        $default = array(
            'exp' => 0,
            'aud' => '',
            'iss' => '',
        );

        $token = array_merge($default, $token);
        $claims = array_merge($default, (array) $claims);

        // Validate expiration
        if (time() >= (int) $token['exp']) {
            throw new Exception('ID Token already expired.');
        }

        // Validate issuer
        if (empty($claims['iss']) || $claims['iss'] !== $token['iss']) {
            throw new Exception('Access Token has a wrong issuer: must contain issuer from OpenId.');
        }

        // Validate audience
        $audience = (array) $token['aud'];
        if (empty($claims['aud']) || ! in_array($claims['aud'], $audience, true)) {
            throw new Exception('Access Token has a wrong audience: must contain clientId.');
        }

        if (count($audience) > 1 && empty($token['azp'])) {
            throw new Exception('Access Token has a wrong audience: must contain azp claim.');
        }

        if (! empty($token['azp']) && $claims['aud'] !== $token['azp']) {
            throw new Exception('Access Token has a wrong audience: has azp but is not the clientId.');
        }
    }

    /**
     * Validate sub from ID token
     *
     * @return boolean
     */
    public function validateSub($userSub)
    {
        $sub = $this->parseIdToken();
        $sub = $sub['sub'] ?? '';

        return $sub === $userSub;
    }

    /**
     * Parse the Access Token
     *
     * @return array
     */
    public function parseAccessToken()
    {
        return $this->parseToken($this->accessToken);
    }

    /**
     * Parse the Id Token
     *
     * @return array
     */
    public function parseIdToken()
    {
        return $this->parseToken($this->idToken);
    }

    /**
     * Get token (access/refresh/id) data
     *
     * @param string $token
     * @return array
     */
    protected function parseToken($token)
    {
        if (! is_string($token)) {
            return [];
        }

        $token = explode('.', $token);
        $token = $this->base64UrlDecode($token[1]);

        return json_decode($token, true);
    }

    /**
     * Base64UrlDecode string
     *
     * @link https://www.php.net/manual/pt_BR/function.base64-encode.php#103849
     *
     * @param  string $data
     * @return string
     */
    protected function base64UrlDecode($data)
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}