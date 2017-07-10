# servant-auth-token-persistent

Storage backend on persistent for [servant-auth-token](https://github.com/NCrashed/servant-auth-token) server.

An itegration of the backend is simple:
``` haskell
-- | Special monad for authorisation actions
newtype AuthM a = AuthM { unAuthM :: PersistentBackendT IO a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadError ServantErr, HasStorage, HasAuthConfig)

-- | Execution of authorisation actions that require 'AuthHandler' context
runAuth :: AuthM a -> ServerM a
runAuth m = do
  cfg <- asks envAuthConfig
  pool <- asks envPool
  liftHandler $ ExceptT $ runPersistentBackendT cfg pool $ unAuthM m
```

Don't forget to add migration to your server startup (if you actually want automatic migrations):
``` haskell
-- | Create new server environment
newServerEnv :: MonadIO m => ServerConfig -> m ServerEnv
newServerEnv cfg = do
  let authConfig = defaultAuthConfig
  pool <- liftIO $ do
    pool <- createPool cfg
    -- run migrations
    flip runSqlPool pool $ runMigration S.migrateAllAuth
    -- create default admin if missing one
    _ <- runPersistentBackendT authConfig pool $ ensureAdmin 17 "admin" "123456" "admin@localhost"
    return pool
  let env = ServerEnv {
        envConfig = cfg
      , envAuthConfig = authConfig
      , envPool = pool
      }
  return env
```

See a full example in [servant-auth-token-example-persistent](https://github.com/NCrashed/servant-auth-token/tree/master/example/persistent).
