<?php

namespace AdvancedLearning\Oauth2Server\Entities;

use AdvancedLearning\Oauth2Server\Repositories\ClientRepository;
use AdvancedLearning\Oauth2Server\Repositories\UserRepository;
use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class AccessTokenEntity implements AccessTokenEntityInterface
{
    use TokenEntityTrait, EntityTrait, AccessTokenTrait;

    /**
     * AccessTokenEntity constructor.
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

    /**
     * Generate a JWT from the access token
     *
     * @return Plain
     */
    public function convertToJWT()
    {
        $this->initJwtConfiguration();

        $now = new DateTimeImmutable();

        $tokenBuilder = $this->jwtConfiguration->builder()
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->getExpiryDateTime())
            ->withClaim('scopes', $this->getScopes());

        // add user name to claims
        if ($this->getUserIdentifier()) {
            $tokenBuilder->relatedTo($this->getUserIdentifier());
            $userEntity = $this->getUserEntity();
            $member = $userEntity->getMember();

            $tokenBuilder->withClaim('fn', $member ? $member->FirstName : null)
                ->withClaim('ln', $member ? $member->Surname : null);
        }

        return $tokenBuilder->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey());
    }

    protected function getUserEntity()
    {
        return $this->getUserIdentifier()
            ? (new UserRepository())->getUserEntityByIdentifier($this->getUserIdentifier())
            : null;
    }
}
