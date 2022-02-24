<?php

namespace AdvancedLearning\Oauth2Server\Entities;

use AdvancedLearning\Oauth2Server\Repositories\UserRepository;
use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
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
     * @param CryptKey $privateKey
     *
     * @return string
     */
    public function convertToJWT(CryptKey $privateKey)
    {
        $now = new DateTimeImmutable();

        $tokenBuilder = (new Builder())
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt(DateTimeImmutable::createFromMutable($this->getExpiryDateTime()))
            ->relatedTo($this->getUserIdentifier())
            ->withClaim('scopes', $this->getScopes());

        // add user name to claims
        if ($this->getUserIdentifier()) {
            $userEntity = $this->getUserEntity();
            $member = $userEntity->getMember();

            $tokenBuilder->withClaim('fn', $member ? $member->FirstName : null)
                ->withClaim('ln', $member ? $member->Surname : null);
        }

        return $tokenBuilder->getToken(new Sha256(), new Key($privateKey->getKeyPath(), $privateKey->getPassPhrase()));
    }

    protected function getUserEntity()
    {
        return (new UserRepository())->getUserEntityByIdentifier($this->getUserIdentifier());
    }
}
