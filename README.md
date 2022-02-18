# SilverStripe Oauth2 Server

[![<advanced-learning>](https://circleci.com/gh/advanced-learning/silverstripe-oauth2-server.svg?style=svg)](<LINK>)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/advanced-learning/silverstripe-oauth2-server/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/advanced-learning/silverstripe-oauth2-server/?branch=master)
[![codecov](https://codecov.io/gh/advanced-learning/silverstripe-oauth2-server/branch/master/graph/badge.svg)](https://codecov.io/gh/advanced-learning/silverstripe-oauth2-server)

OAuth2 server for SilverStripe 4.

## Requirements

* `silverstripe/framework` ^4.0
* `league/oauth2-server`
* `robbie/psr7-adapters`
* `PHP >= 7.1`

## Installation

Install with [Composer](https://getcomposer.org):

```shell
composer require advanced-learning/silverstripe-oauth2-server
```

## Oauth Support

Currently supports client and password grants. The client grant uses the endpoint '/oauth/authorizse'.
Currently requires securing api endpoints manually. There is a middleware but this would affect all requests.
The same logic could be used in conjunction with allowed_actions on the controller.

