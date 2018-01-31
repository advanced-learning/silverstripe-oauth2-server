<?php

namespace AdvancedLearning\Oauth2Server\AuthorizationServer;

use League\OAuth2\Server\AuthorizationServer;

interface Generator
{
    /**
     * Get the Authorization Server.
     *
     * @return AuthorizationServer
     */
    public function getServer(): AuthorizationServer;
}