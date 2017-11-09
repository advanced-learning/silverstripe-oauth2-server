<?php

namespace AdvancedLearning\Oauth2Server\Entities;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class AccessToken implements AccessTokenEntityInterface
{
    use TokenEntityTrait, EntityTrait, AccessTokenTrait;

    /**
     * AccessToken constructor.
     *
     * @param null|string $userIdentifier The identifier of the user.
     * @param array       $scopes         The scopes to assign the user.
     */
    public function __construct(?string $userIdentifier, array $scopes)
    {
        $this->setUserIdentifier($userIdentifier);

        foreach ($scopes as $scope) {
            $this->addScope($scope);
        }
    }
}
