<?php

namespace AdvancedLearning\Oauth2Server\Extensions;

use AdvancedLearning\Oauth2Server\Models\Scope;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldConfig_RelationEditor;
use SilverStripe\ORM\DataExtension;

/**
 * Optionally adds scopes to groups, allows checking permissions for a Member based on scopes.
 *
 * @package AdvancedLearning\Oauth2Server\Extensions
 */
class GroupExtension extends DataExtension
{
    private static $many_many = [
        'Scopes' => Scope::class
    ];

    public function updateCMSFields(FieldList $fields)
    {
        $fields->addFieldToTab('Root.Oauth', GridField::create(
            'Scopes',
            'Scopes',
            $this->owner->Scopes(),
            GridFieldConfig_RelationEditor::create()
        ));
    }
}