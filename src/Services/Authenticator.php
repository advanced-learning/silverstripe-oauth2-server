<?php
/**
 * Created by PhpStorm.
 * User: Conrad
 * Date: 17/11/2017
 * Time: 11:23 AM
 */

namespace AdvancedLearning\Oauth2Server\Services;


use AdvancedLearning\Oauth2Server\Exceptions\AuthenticationException;
use League\OAuth2\Server\ResourceServer;
use SilverStripe\Control\HTTPRequest;

interface Authenticator
{
    /**
     * Authenticate the request. Returns modified request (probably not as SS doesn't support
     * request attributes).
     *
     * @param HTTPRequest $request The SilverStripe request object to be authenticated.
     *
     * @return HTTPRequest
     * @throws AuthenticationException
     */
    public function authenticate(HTTPRequest $request): HTTPRequest;

    /**
     * Override the default ResourceServer.
     *
     * @param ResourceServer $v The new ResourceServer to use.
     *
     * @return $this
     */
    public function setServer(ResourceServer $v): Authenticator;

    /**
     * Get the ResourceServer.
     *
     * @return ResourceServer
     */
    public function getServer(): ResourceServer;
}