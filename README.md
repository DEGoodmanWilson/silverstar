# silverstar

A user authentication microservice in modern C++. Silverstar authenticates that a person accessing the service owns
the requested account by checking the email address and password provided against store (and hashed!) values. Silverstar
also provides user registration features as well.

Silverstar allows users to
- register themselves with a password and email
- confirm their email address after registration, to complete registration process
- authenticate with password in email ine exchange for a time-limited JWT
- change their password
- change their email (not yet implemented)
- logout (invalidates their JWT) (not yet implemented)

Silverstar is _not_ an authorization microservice. That is, Silverstar doesn't keep track of what accounts are allowed
to _do_. You'll need an additional microservice for that :D

## Configuration

- You'll need a Mailgun account for transactional emails
- You'll also need a MongoDB server to persist user data.
- Copy `silverstar.json.sample` to `silverstar.json` and complete it.
- You'll need to also set up the following env vars
  - `MONGO_URI` — the URI to your mongo instance
  - `MAILGUN_API_KEY` — your Mailgun API key
  - `PUBLIC_KEY` — A public key in PEM format, base64 encoded, no password
  - `PRIVATE_KEY` — A private key in PEM format, base64 encoded, no password

You can generate the public/private keypair like this: TODO

## Endpoints!

* `POST /api/v1/register`

* `GET  /api/v1/confirm`

* `GET  /api/v1/login`

* `POST /api/v1/password`

## TODO

- Unclear if storing private key in memory is a security issue.
- Allow passing env vars in a .env file
- Allow passing keys by filename
- 2FA
- OAuth2
- SAML?
- Automated user provisioning (for example, for users who are also employees). Is this in scope or not?
- Auth0?
- Abstract away transactional email provider into drivers
- Abstract away persistence layer into drivers
