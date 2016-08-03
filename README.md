# servant-auth-token

The repo contains server implementation of [servant-auth-toke-api](https://github.com/NCrashed/servant-auth-token-api).

# How to add to your server

To use the server as constituent part, you need to provide customised 'AuthConfig' for 
'authServer' function and implement 'AuthMonad' instance for your handler monad.

``` haskell
import Servant.Server.Auth.Token as Auth

-- | Example of user side configuration
data Config = Config {
  -- | Authorisation specific configuration
  authConfig :: AuthConfig
  -- other fields
  -- ...
}

-- | Example of user side handler monad
newtype App a = App { 
    runApp :: ReaderT Config (ExceptT ServantErr IO) a
  } deriving ( Functor, Applicative, Monad, MonadReader Config,
               MonadError ServantErr, MonadIO)

-- | Now you can use authorisation API in your handler
instance AuthMonad App where 
  getAuthConfig = asks authConfig
  liftAuthAction = App . lift

-- | Include auth 'migrateAll' function into your migration code
doMigrations :: SqlPersistT IO ()
doMigrations = runMigrationUnsafe $ do 
  migrateAll -- other user migrations
  Auth.migrateAll -- creation of authorisation entities
  -- optional creation of default admin if db is empty
  ensureAdmin 17 "admin" "123456" "admin@localhost" 
```

Now you can use 'guardAuthToken' to check authorisation headers in endpoints of your server:

``` haskell
-- | Read a single customer from DB
customerGet :: CustomerId -- ^ Customer unique id
  -> MToken '["customer-read"] -- ^ Required permissions for auth token
  -> App Customer -- ^ Customer data
customerGet i token = do
  guardAuthToken token 
  runDB404 "customer" $ getCustomer i 
```