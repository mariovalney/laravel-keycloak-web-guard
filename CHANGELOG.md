# CHANGELOG

All notable changes to this project will be documented in this file.

### [2.2.0] - 2020-09-13

* Implementing more auth checks.

Props: @cyrillbolliger (for code review)

* Support to laravel Gate.

### [2.1.1] - 2020-09-01

* Implementing state check on authorization flow.

Cyrill Bolliger alerted us today we were not using 'state' param on authentication request.
He did a responsible disclosure to sending a e-mail and we are very grateful (I hope pay him a beer/coffee someday).

Props: @cyrillbolliger (for code review)

### [2.1.0] - 2020-08-26

* ClientID as method to allow override

### [2.0.0] - 2020-06-01

* OpenID configuration refactored.

We'll request only if necessary.
It's a breaking change if you extend **Services/KeycloakService.php**.

Props: @matthewhall-ca

### [1.0.0 ~ 2.0.0] - 2020-06-05

We start CHANGELOG on 2.0.0 ...
So, here is a lot of changes to make the plugin stable.

* Configurations
* Auth based on Laravel
* Check of a role from Keycloak user profile
* Middleware for route access based on role
* Guzzle client options

### [1.0.0] - 2019-06-05

It's alive!

