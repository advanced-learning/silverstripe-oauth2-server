<?php

namespace AdvancedLearning\Oauth2Server\Models;

use function base64_encode;
use SilverStripe\ORM\DataObject;

class Client extends DataObject
{
    private static $table_name = 'OauthClient';

    private static $db = [
        'Name' => 'Varchar(100)',
        'Grants' => 'Varchar(255)',
        'Secret' => 'Varchar(255)'
    ];

    private static $summary_fields = [
        'Name'
    ];

    /**
     * Checks whether this Client has the given grant type.
     *
     * @param string $grantType The grant type to check.
     *
     * @return boolean
     */
    public function hasGrantType($grantType)
    {
        $grants = explode(',', $this->Grants);

        return $grants && in_array($grantType, $grants);
    }

    /**
     * On before write. Generate a secret if we don't have one.
     */
    public function onBeforeWrite()
    {
        parent::onBeforeWrite();

        if (empty($this->Secret)) {
            $this->Secret = $this->generateSecret();
        }
    }

    /**
     * Generate a random secret.
     *
     * @return string
     */
    protected function generateSecret()
    {
        return base64_encode(random_bytes(32));
    }
}
