<?php

namespace AdvancedLearning\Oauth2Server\Repositories;


use AdvancedLearning\Oauth2Server\Entities\AccessToken;
use AdvancedLearning\Oauth2Server\Models\AccessToken as AccessTokenModel;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
        $newToken = AccessTokenModel::create();

        $newToken->Identifier = $accessTokenEntity->getIdentifier();
        $newToken->MemberID = $accessTokenEntity->getClient()->getIdentifier();
        $newToken->Name = $accessTokenEntity->getClient()->getName();
        $newToken->ExpiryDateTime = $accessTokenEntity->getExpiryDateTime()->format('Y-m-d H:i');

        // turn scopes into space separated string
        $newToken->Scopes = '';
        $separator = '';
        foreach ($accessTokenEntity->getScopes() as $scope) {
            $newToken->Scopes .= $separator . $scope->getIdentifier();
            $separator = ' ';
        }

        $newToken->write();

        return $newToken;
    }

    /**
     * {@inheritdoc}
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null)
    {
        return new AccessToken($userIdentifier, $scopes);
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken($tokenId)
    {
        if ($token = $this->findToken($tokenId)) {
            $token->Revoked = true;
            $token->write();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isAccessTokenRevoked($tokenId)
    {
        $token = $this->findToken($tokenId);

        // return true if there is no matching token
        return !$token || $token->Revoked;
    }

    /**
     * Find the Token for passed id.
     *
     * @param mixed $tokenId The id of the token.
     *
     * @return AccessTokenModel
     */
    public function findToken($tokenId)
    {
        return AccessTokenModel::get()->byID($tokenId);
    }
}
