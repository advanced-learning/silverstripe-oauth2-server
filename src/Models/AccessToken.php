<?php

namespace AdvancedLearning\Oauth2Server\Models;

use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;

/**
 * Class AccessTokenEntity
 *
 * @package AdvancedLearning\Oauth2Server\Models
 *
 * @property int    $ID
 * @property string $Identifier
 * @property string $Scopes
 * @property string $Name
 * @property string $ExpiryDateTime
 * @property bool   $Revoked
 */
class AccessToken extends DataObject
{
    private static $table_name = 'OauthAccessToken';

    private static $db = [
        'Identifier' => 'Varchar(255)',
        'Scopes' => 'Text',
        'Name' => 'Varchar(255)',
        'ExpireDateTime' => 'Datetime',
        'Revoked' => 'Boolean',
        'User' => 'Varchar(50)'
    ];

    private static $summary_fields = [
        'Name',
        'ExpireDateTime',
        'Revoked'
    ];
}
