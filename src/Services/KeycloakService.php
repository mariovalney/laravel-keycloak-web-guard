<?php

namespace Vizir\KeycloakWebGuard\Services;

use Exception;
use Illuminate\Support\Arr;
use GuzzleHttp\ClientInterface;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;
use GuzzleHttp\Exception\GuzzleException;
use Vizir\KeycloakWebGuard\Auth\KeycloakAccessToken;

class KeycloakService
{
    use OpenIdConfiguration, Uma2Configuration;

    /**
     * The Session key for token
     */
    const KEYCLOAK_SESSION = '_keycloak_token';

    /**
     * The Session key for state
     */
    const KEYCLOAK_SESSION_STATE = '_keycloak_state';

    /**
     * Keycloak URL
     *
     * @var string
     */
    protected $baseUrl;

    /**
     * Keycloak Realm
     *
     * @var string
     */
    protected $realm;

    /**
     * Keycloak Client ID
     *
     * @var string
     */
    protected $clientId;

    /**
     * Keycloak Client Secret
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * CallbackUrl
     *
     * @var array
     */
    protected $callbackUrl;

    /**
     * RedirectLogout
     *
     * @var array
     */
    protected $redirectLogout;

    /**
     * The state for authorization request
     *
     * @var string
     */
    protected $state;

    /**
     * The HTTP Client
     *
     * @var ClientInterface
     */
    protected $httpClient;

    /**
     * The Constructor
     * You can extend this service setting protected variables before call
     * parent constructor to comunicate with Keycloak smoothly.
     *
     * @param ClientInterface $client
     * @return void
     */
    public function __construct(ClientInterface $client)
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim(Config::get('keycloak-web.base_url'), '/');
        }

        if (is_null($this->realm)) {
            $this->realm = Config::get('keycloak-web.realm');
        }

        if (is_null($this->clientId)) {
            $this->clientId = Config::get('keycloak-web.client_id');
        }

        if (is_null($this->clientSecret)) {
            $this->clientSecret = Config::get('keycloak-web.client_secret');
        }

        if (is_null($this->cacheOpenid)) {
            $this->cacheOpenid = Config::get('keycloak-web.cache_openid', false);
        }

        if (is_null($this->cacheUma2)) {
            $this->cacheUma2 = Config::get('keycloak-web.cache_uma2', false);
        }

        if (is_null($this->callbackUrl)) {
            $this->callbackUrl = route('keycloak.callback');
        }

        if (is_null($this->redirectLogout)) {
            $this->redirectLogout = Config::get('keycloak-web.redirect_logout');
        }

        $this->state = $this->generateRandomState();
        $this->httpClient = $client;
    }

    /**
     * Return the login URL
     *
     * @link https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
     *
     * @return string
     */
    public function getLoginUrl()
    {
        $url = $this->getOpenIdValue('authorization_endpoint');
        $params = [
            'scope' => 'openid',
            'response_type' => 'code',
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->callbackUrl,
            'state' => $this->getState(),
        ];

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the logout URL
     *
     * @return string
     */
    public function getLogoutUrl()
    {
        $url = $this->getOpenIdValue('end_session_endpoint');

        if (empty($this->redirectLogout)) {
            $this->redirectLogout = url('/');
        }

        $params = [
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->redirectLogout,
        ];

        return $this->buildUrl($url, $params);
    }

    /**
     * Return the register URL
     *
     * @link https://stackoverflow.com/questions/51514437/keycloak-direct-user-link-registration
     *
     * @return string
     */
    public function getRegisterUrl()
    {
        $url = $this->getLoginUrl();
        return str_replace('/auth?', '/registrations?', $url);
    }
    /**
     * Get access token from Code
     *
     * @param  string $code
     * @return array
     */
    public function getAccessToken($code)
    {
        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'code' => $code,
            'client_id' => $this->getClientId(),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Refresh access token
     *
     * @param  string $refreshToken
     * @return array
     */
    public function refreshAccessToken($credentials)
    {
        if (empty($credentials['refresh_token'])) {
            return [];
        }

        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'grant_type' => 'refresh_token',
            'refresh_token' => $credentials['refresh_token'],
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return $token;
    }

    /**
     * Invalidate Refresh
     *
     * @param  string $refreshToken
     * @return array
     */
    public function invalidateRefreshToken($refreshToken)
    {
        $url = $this->getOpenIdValue('end_session_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'refresh_token' => $refreshToken,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);
            return $response->getStatusCode() === 204;
        } catch (GuzzleException $e) {
            $this->logException($e);
        }

        return false;
    }

    /**
     * Get access token from Code
     * @param  array $credentials
     * @return array
     */
    public function getUserProfile($credentials)
    {
        $credentials = $this->refreshTokenIfNeeded($credentials);

        $user = [];
        try {
            // Validate JWT Token
            $token = new KeycloakAccessToken($credentials);

            if (empty($token->getAccessToken())) {
                throw new Exception('Access Token is invalid.');
            }

            $claims = array(
                'aud' => $this->getClientId(),
                'iss' => $this->getOpenIdValue('issuer'),
            );

            $token->validateIdToken($claims);

            // Get userinfo
            $url = $this->getOpenIdValue('userinfo_endpoint');
            $headers = [
                'Authorization' => 'Bearer ' . $token->getAccessToken(),
                'Accept' => 'application/json',
            ];

            $response = $this->httpClient->request('GET', $url, ['headers' => $headers]);

            if ($response->getStatusCode() !== 200) {
                throw new Exception('Was not able to get userinfo (not 200)');
            }

            $user = $response->getBody()->getContents();
            $user = json_decode($user, true);

            // Validate retrieved user is owner of token
            $token->validateSub($user['sub'] ?? '');
        } catch (GuzzleException $e) {
            $this->logException($e);
        } catch (Exception $e) {
            Log::error('[Keycloak Service] ' . print_r($e->getMessage(), true));
        }

        return $user;
    }

    /**
     * Retrieve Token from Session
     *
     * @return array|null
     */
    public function retrieveToken()
    {
        return session()->get(self::KEYCLOAK_SESSION);
    }

    /**
     * Save Token to Session
     *
     * @return void
     */
    public function saveToken($credentials)
    {
        session()->put(self::KEYCLOAK_SESSION, $credentials);
        session()->save();
    }

    /**
     * Remove Token from Session
     *
     * @return void
     */
    public function forgetToken()
    {
        session()->forget(self::KEYCLOAK_SESSION);
        session()->save();
    }

    /**
     * Validate State from Session
     *
     * @return void
     */
    public function validateState($state)
    {
        $challenge = session()->get(self::KEYCLOAK_SESSION_STATE);
        return (! empty($state) && ! empty($challenge) && $challenge === $state);
    }

    /**
     * Save State to Session
     *
     * @return void
     */
    public function saveState()
    {
        session()->put(self::KEYCLOAK_SESSION_STATE, $this->state);
        session()->save();
    }

    /**
     * Remove State from Session
     *
     * @return void
     */
    public function forgetState()
    {
        session()->forget(self::KEYCLOAK_SESSION_STATE);
        session()->save();
    }

    /**
     * Build a URL with params
     *
     * @param  string $url
     * @param  array $params
     * @return string
     */
    public function buildUrl($url, $params)
    {
        $parsedUrl = parse_url($url);
        if (empty($parsedUrl['host'])) {
            return trim($url, '?') . '?' . Arr::query($params);
        }

        if (! empty($parsedUrl['port'])) {
            $parsedUrl['host'] .= ':' . $parsedUrl['port'];
        }

        $parsedUrl['scheme'] = (empty($parsedUrl['scheme'])) ? 'https' : $parsedUrl['scheme'];
        $parsedUrl['path'] = (empty($parsedUrl['path'])) ? '' : $parsedUrl['path'];

        $url = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . $parsedUrl['path'];
        $query = [];

        if (! empty($parsedUrl['query'])) {
            $parsedUrl['query'] = explode('&', $parsedUrl['query']);

            foreach ($parsedUrl['query'] as $value) {
                $value = explode('=', $value);

                if (count($value) < 2) {
                    continue;
                }

                $key = array_shift($value);
                $value = implode('=', $value);

                $query[$key] = urldecode($value);
            }
        }

        $query = array_merge($query, $params);

        return $url . '?' . Arr::query($query);
    }

    /**
     * Return the client id for requests
     *
     * @return string
     */
    protected function getClientId()
    {
        return $this->clientId;
    }

    /**
     * Return the state for requests
     *
     * @return string
     */
    protected function getState()
    {
        return $this->state;
    }

    /**
     * Check we need to refresh token and refresh if needed
     *
     * @param  array $credentials
     * @return array
     */
    protected function refreshTokenIfNeeded($credentials)
    {
        if (! is_array($credentials) || empty($credentials['access_token']) || empty($credentials['refresh_token'])) {
            return $credentials;
        }

        $token = new KeycloakAccessToken($credentials);
        if (! $token->hasExpired()) {
            return $credentials;
        }

        $credentials = $this->refreshAccessToken($credentials);

        if (empty($credentials['access_token'])) {
            $this->forgetToken();
            return [];
        }

        $this->saveToken($credentials);
        return $credentials;
    }

    /**
     * Log a GuzzleException
     *
     * @param  GuzzleException $e
     * @return void
     */
    protected function logException(GuzzleException $e)
    {
        // Guzzle 7
        if (! method_exists($e, 'getResponse') || empty($e->getResponse())) {
            Log::error('[Keycloak Service] ' . $e->getMessage());
            return;
        }

        $error = [
            'request' => method_exists($e, 'getRequest') ? $e->getRequest() : '',
            'response' => $e->getResponse()->getBody()->getContents(),
        ];

        Log::error('[Keycloak Service] ' . print_r($error, true));
    }

    /**
     * Return a random state parameter for authorization
     *
     * @return string
     */
    protected function generateRandomState()
    {
        return bin2hex(random_bytes(16));
    }
}
