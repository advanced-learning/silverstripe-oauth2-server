<?php

namespace AdvancedLearning\Oauth2Server\Repositories;


use AdvancedLearning\Oauth2Server\Entities\RefreshTokenEntity;
use AdvancedLearning\Oauth2Server\Models\AccessToken;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity)
    {
        $newToken = AccessToken::create();

        $newToken->Identifier = $refreshTokenEntity->getIdentifier();
        $newToken->Name = $refreshTokenEntity->getAccessToken()->getClient()->getName();
        $newToken->ExpiryDateTime = $refreshTokenEntity->getExpiryDateTime()->format('Y-m-d H:i');

        // turn scopes into space separated string
        $newToken->Scopes = '';
        $separator = '';
        foreach ($refreshTokenEntity->getAccessToken()->getScopes() as $scope) {
            $newToken->Scopes .= $separator . $scope->getIdentifier();
            $separator = ' ';
        }

        $newToken->write();

        return $newToken;
    }

    /**
     * {@inheritdoc}
     */
    public function getNewRefreshToken()
    {
        return new RefreshTokenEntity();
    }

    /**
     * {@inheritdoc}
     */
    public function revokeRefreshToken($tokenId)
    {
        if ($token = $this->findToken($tokenId)) {
            $token->Revoked = true;
            $token->write();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function isRefreshTokenRevoked($tokenId)
    {
        $token = $this->findToken($tokenId);

        // return true if there is no matching token
        return empty($token) || $token->Revoked;
    }

    /**
     * Find the Token for passed id.
     *
     * @param string $tokenId The id of the token.
     *
     * @return AccessToken|null
     */
    public function findToken(string $tokenId): ?AccessToken
    {
        return AccessToken::get()->filter(['Identifier' => $tokenId])->first();
    }
}
