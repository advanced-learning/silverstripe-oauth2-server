<?php

namespace AdvancedLearning\Oauth2Server\Repositories;

use AdvancedLearning\Oauth2Server\Entities\ScopeEntity;
use AdvancedLearning\Oauth2Server\Models\Scope;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

class ScopeRepository implements ScopeRepositoryInterface
{
    /**
     * {@inheritDoc}
     */
    public function getScopeEntityByIdentifier($identifier)
    {
        if ($scope = Scope::get()->filter(['Name' => $identifier])->first()) {
            return new ScopeEntity($identifier);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function finalizeScopes(
        array $scopes,
        $grantType,
        ClientEntityInterface $clientEntity,
        $userIdentifier = null
    ) {
        // only check if we have a user, should a client have scopes?
        if (empty($userIdentifier)) return $scopes;

        $userEntity = (new UserRepository())->getUserEntityByIdentifier($userIdentifier);

        $approvedScopes = [];
        foreach ($scopes as $scope) {
            if ($userEntity->hasScope($scope->getIdentifier())) {
                $approvedScopes[] = $scope;
            }
        }
        return $approvedScopes;
    }
}
