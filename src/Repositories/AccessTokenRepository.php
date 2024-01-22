<?php

namespace AdvancedLearning\Oauth2Server\Repositories;

use AdvancedLearning\Oauth2Server\Entities\AccessTokenEntity as AccessTokenEntity;
use AdvancedLearning\Oauth2Server\Models\AccessToken;
use Carbon\Carbon;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use SilverStripe\ORM\DB;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
        $newToken = AccessToken::create();

        $newToken->Identifier = $accessTokenEntity->getIdentifier();
        $newToken->Name = $accessTokenEntity->getClient()->getName();
        $newToken->User = $accessTokenEntity->getUserIdentifier();
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
        $token = new AccessTokenEntity($userIdentifier, $scopes);
        $token->setClient($clientEntity);
        return $token;
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
    public function isAccessTokenRevoked($tokenId): bool
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

    /**
     * Delete tokens which have expired.
     *
     * @param integer $days
     */
    public function deleteExpiredTokens($days = 1)
    {
        $expiryDate = Carbon::now()->subDays($days);
        DB::query(sprintf(
            'DELETE FROM "OauthAccessToken" WHERE "ExpiryDateTime" < \'%s\'',
            $expiryDate->toDateTimeString()
        ));
    }
}
