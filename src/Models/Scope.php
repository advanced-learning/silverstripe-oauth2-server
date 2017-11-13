<?php

namespace AdvancedLearning\Oauth2Server\Models;

use SilverStripe\ORM\DataObject;

/**
 * Class ScopeEntity
 *
 * @package AdvancedLearning\Oauth2Server\Models
 *
 * @property string $Name
 * @property string $Description
 */
class Scope extends DataObject
{
    private static $table_name = 'OauthScope';

    private static $db = [
        'Name' => 'Varchar(100)',
        'Description' => 'Varchar(255)'
    ];

    private static $summary_fields = [
        'Name',
        'Description'
    ];
}
