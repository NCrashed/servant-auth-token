0.6.0.0
=======

* Breaking changes in `servant-auth-token-0.5.0.0`.

0.5.1.1
=======

* Relax `servant` and `servant-server` versions.

0.5.1.0
=======

* Fix instances of `ConvertStorage` that causes #12

0.5.0.0
=======

* MTL instances for `PersistentBackendT`. Use `liftDB` instead of removed `MonadReader SqlBackend` instance.

0.3.2.0
=======

* Initial factor out from parent package.
