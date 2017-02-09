# servant-auth-token-acid

Storage backend on acid for [servant-auth-token](https://github.com/NCrashed/servant-auth-token) server.

As `acid-state` is bad at composing states, the integration of the library in your project requires a massive TH mixins.
The authentification state's queries are simply copied to your app.

First, define you own global `acid-state` type:

``` haskell
import Data.SafeCopy
import Servant.Server.Auth.Token.Acid.Schema as A

-- | Application global state for acid-state
data DB = DB {
  dbAuth :: A.Model -- ^ Storage for Auth state
, dbCustom :: () -- ^ Demo of custom state
}

-- | Generation of inital state
newDB :: DB
newDB = DB {
    dbAuth = A.newModel
  , dbCustom = ()
  }

-- | Extraction of Auth model from global state
instance HasModelRead DB where
  askModel = dbAuth

-- | Extraction of Auth model from global state
instance HasModelWrite DB where
  putModel db m = db { dbAuth = m }

deriveSafeCopy 0 'base ''DB

-- Mixin auth state queries and derive acid-state instances for them
A.deriveQueries ''DB
A.makeModelAcidic ''DB
```

Next, define your monad stack for the authorization actions:
``` haskell
-- Derive HasStorage for 'AcidBackendT' with your 'DB'.
-- It is important that it is come before the below newtype
deriveAcidHasStorage ''DB

-- | Special monad for authorisation actions
newtype AuthM a = AuthM { unAuthM :: AcidBackendT DB IO a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadError ServantErr, HasAuthConfig, HasStorage)

-- | Execution of authorisation actions that require 'AuthHandler' context
runAuth :: AuthM a -> ServerM a
runAuth m = do
  cfg <- asks envAuthConfig
  db <- asks envDB
  liftHandler $ ExceptT $ runAcidBackendT cfg db $ unAuthM m
```

See a full example in [servant-auth-token-example-acid](https://github.com/NCrashed/servant-auth-token/tree/master/example/acid).
