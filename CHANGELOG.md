0.4.6.0
=======

* Add `withAuthToken` to guard groups of endpoints.

0.4.5.0
=======

* Auto deriving `HasAuthConfig` and `HasStorage` for transformers.

0.4.4.1
=======

* `persistent-postgresql` is not actually used

0.4.4.0
=======

* Add `signinByHashUnsafe` for internal usage.

0.4.3.0
=======

* Implementation for `AuthFindUserByLogin` endpoint.
* Feature to manipulate with hashes of passwords. For instance, now you can store
hashed admin password in config.

0.4.2.0
=======

* Add implementation for `AuthCheckPermissionsMethod` and `AuthGetUserIdMethod` endpoints.

0.4.1.1
=======

* Relax `aeson` and `opt-parse-applicative` bounds.
* Add `monad-control` instances.

0.4.1.0
=======

* Remove persistent dependencies from abstract package.

0.4.0.0
=======

* Abstract over storage: persistent and acid-state backends.

0.3.2.0
=======

* Support lts-7.1 (ghc 8 and persistent-0.6)

0.3.0.0
=======

* Add authorisation by single usage codes.

0.2.0.1
=======

* Relax boundaries for ghc 8.0.1.

0.2.0.0
=======

* Implement `servant-auth-token-0.2.0.0` API.

0.1.2.0
=======

* Expose implementation of API for embedding in complex servers.

0.1.1.0
=======

* Added `restoreCodeGenerator` to configuration

0.1.0.0
=======

* Initial publication
