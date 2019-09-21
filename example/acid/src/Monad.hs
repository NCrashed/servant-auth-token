{-# OPTIONS_GHC -fno-warn-orphans #-}
module Monad(
    ServerEnv(..)
  , ServerM
  , newServerEnv
  , runServerM
  , runServerMIO
  , AuthM(..)
  , runAuth
  ) where

import Control.Monad.Base
import Control.Monad.Catch (MonadCatch, MonadThrow)
import Control.Monad.Except
import Control.Monad.Logger
import Control.Monad.Reader
import Control.Monad.Trans.Control
import Data.Acid
import Data.Monoid
import Data.Text (unpack)
import Servant.Server
import Servant.Server.Auth.Token.Acid as A
import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.Model

import Config
import DB

-- | Server private environment
data ServerEnv = ServerEnv {
  -- | Configuration used to create the server
  envConfig      :: !ServerConfig
  -- | Configuration of auth server
, envAuthConfig  :: !AuthConfig
  -- | DB state
, envDB          :: !(AcidState DB)
}

-- | Create new server environment
newServerEnv :: MonadIO m => ServerConfig -> m ServerEnv
newServerEnv cfg = do
  let authConfig = defaultAuthConfig
  db <- liftIO $ openLocalStateFrom (unpack $ serverDbPath cfg) newDB
  -- ensure default admin if missing one
  _ <- runAcidBackendT authConfig db $ ensureAdmin 17 "admin" "123456" "admin@localhost"
  let env = ServerEnv {
        envConfig = cfg
      , envAuthConfig = authConfig
      , envDB = db
      }
  return env

-- | Server monad that holds internal environment
newtype ServerM a = ServerM { unServerM :: ReaderT ServerEnv (LoggingT Handler) a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadBase IO, MonadReader ServerEnv
    , MonadLogger, MonadLoggerIO, MonadThrow, MonadCatch, MonadError ServerError)

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
  ea <- runHandler $ runServerM env m
  case ea of
    Left e -> fail $ "runServerMIO: " <> show e
    Right a -> return a

-- Derive HasStorage for 'AcidBackendT' with your 'DB'
deriveAcidHasStorage ''DB

-- | Special monad for authorisation actions
newtype AuthM a = AuthM { unAuthM :: AcidBackendT DB IO a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadError ServerError, HasAuthConfig, HasStorage)

-- | Execution of authorisation actions that require 'AuthHandler' context
runAuth :: AuthM a -> ServerM a
runAuth m = do
  cfg <- asks envAuthConfig
  db <- asks envDB
  liftHandler $ Handler. ExceptT $ runAcidBackendT cfg db $ unAuthM m
