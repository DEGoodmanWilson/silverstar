# silverstar

A user authentication microservice in modern C++.

Allows users to
- register themselves with a password and email
- confirm their email address after registration, to complete registration process
- authenticate with password in email ine exchange for a time-limited JWT
- change their password
- logout (invalidates their JWT) (not yet implemented)

## Endpoints!

* `POST /api/v1/register`

* `GET  /api/v1/confirm`

* `GET  /api/v1/login`

* `POST /api/v1/password`