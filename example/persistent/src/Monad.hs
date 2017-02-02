module Monad(
    ServerEnv(..)
  , ServerM
  , newServerEnv
  , runServerM
  , runServerMIO
  , serverMtoHandler
  , AuthM(..)
  , runAuth
  ) where

import Control.Monad.Base
import Control.Monad.Catch (MonadCatch, MonadThrow)
import Control.Monad.Except
import Control.Monad.Logger
import Control.Monad.Reader
import Control.Monad.Trans.Control
import Data.Monoid
import Database.Persist.Sql
import Servant.Server
import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.Model
import Servant.Server.Auth.Token.Persistent

import qualified Servant.Server.Auth.Token.Persistent.Schema as S

import Config

-- | Server private environment
data ServerEnv = ServerEnv {
  -- | Configuration used to create the server
  envConfig      :: !ServerConfig
  -- | Configuration of auth server
, envAuthConfig  :: !AuthConfig
  -- | DB pool
, envPool        :: !ConnectionPool
}

-- | Create new server environment
newServerEnv :: MonadIO m => ServerConfig -> m ServerEnv
newServerEnv cfg = do
  pool <- liftIO $ do
    pool <- createPool cfg
    runSqlPool (runMigration S.migrateAll) pool
    return pool
  let env = ServerEnv {
        envConfig = cfg
      , envAuthConfig = defaultAuthConfig
      , envPool = pool
      }
  return env

-- | Server monad that holds internal environment
newtype ServerM a = ServerM { unServerM :: ReaderT ServerEnv (LoggingT Handler) a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadBase IO, MonadReader ServerEnv
    , MonadLogger, MonadLoggerIO, MonadThrow, MonadCatch, MonadError ServantErr)

newtype StMServerM a = StMServerM { unStMServerM :: StM (ReaderT ServerEnv (LoggingT Handler)) a }

instance MonadBaseControl IO ServerM where
    type StM ServerM a = StMServerM a
    liftBaseWith f = ServerM $ liftBaseWith $ \q -> f (fmap StMServerM . q . unServerM)
    restoreM = ServerM . restoreM . unStMServerM

-- | Lift servant monad to server monad
liftHandler :: Handler a -> ServerM a
liftHandler = ServerM . lift . lift

-- | Execution of 'ServerM'
runServerM :: ServerEnv -> ServerM a -> Handler a
runServerM e = runStdoutLoggingT . flip runReaderT e . unServerM

-- | Execution of 'ServerM' in IO monad
runServerMIO :: ServerEnv -> ServerM a -> IO a
runServerMIO env m = do
  ea <- runExceptT $ runServerM env m
  case ea of
    Left e -> fail $ "runServerMIO: " <> show e
    Right a -> return a

-- | Transformation to Servant 'Handler'
serverMtoHandler :: ServerEnv -> ServerM :~> Handler
serverMtoHandler e = Nat (runServerM e)

-- | Special monad for authorisation actions
newtype AuthM a = AuthM { unAuthM :: PersistentBackendT IO a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadError ServantErr, HasStorage, HasAuthConfig)

-- | Execution of authorisation actions that require 'AuthHandler' context
runAuth :: AuthM a -> ServerM a
runAuth m = do
  cfg <- asks envAuthConfig
  pool <- asks envPool
  liftHandler $ ExceptT $ runPersistentBackendT cfg pool $ unAuthM m
