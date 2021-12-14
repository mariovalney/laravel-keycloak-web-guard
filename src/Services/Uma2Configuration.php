<?php

namespace Vizir\KeycloakWebGuard\Services;

use App\Models\User;
use Exception;
use GuzzleHttp\Exception\GuzzleException;
use http\Exception\InvalidArgumentException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Log;
use Vizir\KeycloakWebGuard\Auth\KeycloakAccessToken;
use Vizir\KeycloakWebGuard\Auth\PartyToken;

trait Uma2Configuration
{
    /**
     * Keycloak Uma2 Configuration
     *
     * @var array
     */
    protected $uma2;

    /**
     * Keycloak Uma2 Cache Configuration
     *
     * @var array
     */
    protected $cacheUma2;

    /**
     * Return resources and scopes for the authenticated user.
     *
     * https://www.keycloak.org/docs/latest/authorization_services/index.html#_service_authorization_api
     *
     * @param array $resources
     * @param array $scopes
     * @throws GuzzleException
     */
    public function authorizations()
    {
        $token = new KeycloakAccessToken($this->retrieveToken());

        $cacheKey = 'keycloak_web_guard_uma2-' . $this->realm . '-' . md5($token->parseAccessToken()['sid']);

        $permissions = Cache::get($cacheKey, []);
        if (!empty($permissions)) {
            return $permissions;
        }

        try {
            $url = $this->getUma2Value('token_endpoint');

            $headers = [
                'Authorization' => 'Bearer ' . $token->getAccessToken(),
                'Accept' => 'application/json',
            ];

            $params = [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:uma-ticket',
                'audience' => $this->getClientId(),
                'response_mode' => 'permissions'
            ];

            $response = $this->httpClient->request('POST', $url, [
                'headers' => $headers,
                'form_params' => $params,
            ]);

            if ($response->getStatusCode() !== 200) {
                throw new Exception('Was not able to get a Request Party Token');
            }

            $response = $response->getBody()->getContents();
            $permissions = json_decode($response, true);

            $permissions = collect($permissions)->map(function($resource){
                return (object)[
                    'name' => $resource['rsname'],
                    'scopes' => $resource['scopes']
                ];
            });

        } catch (GuzzleException $e) {
            $this->logException($e);
        } catch (Exception $e) {
            Log::error('[Keycloak Service] ' . print_r($e->getMessage(), true));
        }


        Cache::put($cacheKey, $permissions);

        return $permissions;
    }

    /**
     * Validate if the authenticated user can access the given resource.
     *
     * @param $resource
     * @return bool
     * @throws GuzzleException
     */
    public function canAccess($resource)
    {

        if (!is_string($resource) || empty($resource)) return false;
        $args = explode(':', $resource);

        if (count($args) == 2) {


            // Check if there an authorized resource on the authorizations list of the user.
            $resource = $this->authorizations()
                ->filter(fn($permission) => $permission->name == $args[0])
                ->first();

            // If there is no resource, it means that is not authorized
            if (!$resource) return false;

            // If the resource exists, we procced to check the scopes
            // If the key scopes doesn't exists, it's because there are not scopes associated to
            // this particular resource, we need a scope
            if (!isset($resource->scopes)) return false;

            // If the key scopes exists we check that the scope passed on the arguments
            // is the one that the user can access
            return in_array($args[1], $resource->scopes);
        }

        throw new InvalidArgumentException("The resource doesn't match the correct format");
    }

    /**
     * Return a value from the Uma2 Configuration
     *
     * @param  string $key
     * @return string
     */
    protected function getUma2Value($key)
    {
        if (! $this->uma2) {
            $this->uma2 = $this->getUma2Configuration();
        }

        return Arr::get($this->uma2, $key);
    }

    /**
     * Retrieve Uma2 Endpoints
     *
     * @return array
     */
    protected function getUma2Configuration()
    {
        $cacheKey = 'keycloak_web_guard_uma2-' . $this->realm . '-' . md5($this->baseUrl);

        // From cache?
        if ($this->cacheUma2) {
            $configuration = Cache::get($cacheKey, []);

            if (! empty($configuration)) {
                return $configuration;
            }
        }

        // Request if cache empty or not using
        $url = $this->baseUrl . '/realms/' . $this->realm;
        $url = $url . '/.well-known/uma2-configuration';

        $configuration = [];

        try {
            $response = $this->httpClient->request('GET', $url);

            if ($response->getStatusCode() === 200) {
                $configuration = $response->getBody()->getContents();
                $configuration = json_decode($configuration, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);

            throw new Exception('[Keycloak Error] It was not possible to load Uma2 configuration: ' . $e->getMessage());
        }

        // Save cache
        if ($this->cacheUma2) {
            Cache::put($cacheKey, $configuration);
        }

        return $configuration;

    }
}
