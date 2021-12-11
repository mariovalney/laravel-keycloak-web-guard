<?php

namespace Vizir\KeycloakWebGuard\Services;

use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;

trait OpenIdConfiguration
{
    /**
     * Keycloak OpenId Configuration
     *
     * @var array
     */
    protected $openid;

    /**
     * Keycloak OpenId Cache Configuration
     *
     * @var array
     */
    protected $cacheOpenid;

    /**
     * Return a value from the Open ID Configuration
     *
     * @param  string $key
     * @return string
     */
    protected function getOpenIdValue($key)
    {
        if (! $this->openid) {
            $this->openid = $this->getOpenIdConfiguration();
        }

        return Arr::get($this->openid, $key);
    }

    /**
     * Retrieve OpenId Endpoints
     *
     * @return array
     */
    protected function getOpenIdConfiguration()
    {
        $cacheKey = 'keycloak_web_guard_openid-' . $this->realm . '-' . md5($this->baseUrl);

        // From cache?
        if ($this->cacheOpenid) {
            $configuration = Cache::get($cacheKey, []);

            if (! empty($configuration)) {
                return $configuration;
            }
        }

        // Request if cache empty or not using
        $url = $this->baseUrl . '/realms/' . $this->realm;
        $url = $url . '/.well-known/openid-configuration';

        $configuration = [];

        try {
            $response = $this->httpClient->request('GET', $url);

            if ($response->getStatusCode() === 200) {
                $configuration = $response->getBody()->getContents();
                $configuration = json_decode($configuration, true);
            }
        } catch (GuzzleException $e) {
            $this->logException($e);

            throw new Exception('[Keycloak Error] It was not possible to load OpenId configuration: ' . $e->getMessage());
        }

        // Save cache
        if ($this->cacheOpenid) {
            Cache::put($cacheKey, $configuration);
        }

        return $configuration;
    }
}
