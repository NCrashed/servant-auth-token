# servant-auth-token

[![Build Status](https://travis-ci.org/NCrashed/servant-auth-token.svg?branch=master)](https://travis-ci.org/NCrashed/servant-auth-token)

The repo contains server implementation of [servant-auth-token-api](https://github.com/NCrashed/servant-auth-token-api).

# How to add to your server

At the moment you have two options for backend storage:

- [persistent backend](https://github.com/NCrashed/servant-auth-token/tree/master/servant-auth-token-persistent) - [persistent](https://hackage.haskell.org/package/persistent) backend, simple to integrate with your app.

- [acid-state backend](https://github.com/NCrashed/servant-auth-token/tree/master/servant-auth-token-acid) - [acid-state](https://hackage.haskell.org/package/acid-state) backend is light solution for in memory storage, but it is more difficult to integrate it with your app.

- Possible candidates for other storage backends: VCache, leveldb, JSON files. To see how to implement them, see [HasStorage](https://github.com/NCrashed/servant-auth-token/blob/master/src/Servant/Server/Auth/Token/Model.hs#L220) type class.

Now you can use 'guardAuthToken' to check authorization headers in endpoints of your server:

``` haskell
-- | Read a single customer from DB
customerGet :: CustomerId -- ^ Customer unique id
  -> MToken '["customer-read"] -- ^ Required permissions for auth token
  -> ServerM Customer -- ^ Customer data
customerGet i token = do
  guardAuthToken token
  runDB404 "customer" $ getCustomer i
```
