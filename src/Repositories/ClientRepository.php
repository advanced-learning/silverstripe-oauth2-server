<?php

namespace AdvancedLearning\Oauth2Server\Repositories;

use AdvancedLearning\Oauth2Server\Entities\ClientEntity;
use AdvancedLearning\Oauth2Server\Models\Client;
use function hash_equals;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use const PHP_EOL;

class ClientRepository implements ClientRepositoryInterface
{
    protected $clients = [];

    /**
     * {@inheritdoc}
     */
    public function getClientEntity($clientIdentifier)
    {
        if (!isset($this->clients[$clientIdentifier])) {
            $this->getClient($clientIdentifier);
        }

        return !empty($this->clients[$clientIdentifier])  ? new ClientEntity($clientIdentifier, $this->clients[$clientIdentifier]->Name, 'something') : null;
    }

    public function validateClient($clientIdentifier, $clientSecret, $grantType)
    {
        if (!isset($this->clients[$clientIdentifier])) {
            $this->getClient($clientIdentifier);
        }

        $client = $this->clients[$clientIdentifier];

        return !(!$client || $clientSecret !== $client->Secret || !$client->hasGrantType($grantType));
    }

    protected function getClient($clientIdentifier)
    {
        $client = Client::get()->filter([
            'Identifier' => $clientIdentifier
        ])->first();

        $this->clients[$clientIdentifier] = $client ?? null;
    }
}
