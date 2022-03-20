# CHANGELOG

All notable changes to this project will be documented in this file.

### [2.3.3] - 2022-03-20

* Support to Laravel 9.0. (props: @alvarofelipems)
* Allow access list roles in the Guard. (props: @socieboy)
* A typo in docs. (props: @atyakresna)

### [2.3.2] - 2021-01-27

* Support to Guzzle 7.

### [2.3.1] - 2021-01-27

* Fixed a problem in the expired check. (props: @gorkagv)

### [2.3.0] - 2020-10-30

* Support to Laravel 8.0. (props: @matthewhall-ca)
* Support to Laravel Gate.

### [2.2.0] - 2020-09-13

* Implementing more auth checks. (props for code review: @cyrillbolliger)
* Support to Laravel Gate.

### [2.1.1] - 2020-09-01

* Implementing state check on authorization flow. (props for code review: @cyrillbolliger)

Cyrill Bolliger alerted us today we were not using 'state' param on authentication request.
He did a responsible disclosure to sending a e-mail and we are very grateful (I hope pay him a beer/coffee someday).

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

