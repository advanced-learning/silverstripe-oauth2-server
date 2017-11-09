<?php

namespace AdvancedLearning\Oauth2Server\Repositories;

use AdvancedLearning\Oauth2Server\Entities\Client;
use function hash_equals;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use const PHP_EOL;

class ClientRepository implements ClientRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getClientEntity($clientIdentifier, $grantType, $clientSecret = null, $mustValidateSecret = true)
    {
        $client = \AdvancedLearning\Oauth2Server\Models\Client::get()->filter([
           'ID' => $clientIdentifier
        ])->first();


        if ($mustValidateSecret && $client && !hash_equals($client->Secret, $clientSecret)) {
            $client = null;
        }

        return $client && $client->hasGrantType($grantType) ? new Client($clientIdentifier, $client->Name, 'something') : null;
    }
}
