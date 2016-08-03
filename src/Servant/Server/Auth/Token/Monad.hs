{-|
Module      : Servant.Server.Auth.Token.Monad
Description : Monad for auth server handler
Copyright   : (c) Anton Gushcha, 2016
License     : MIT
Maintainer  : ncrashed@gmail.com
Stability   : experimental
Portability : Portable
-}
module Servant.Server.Auth.Token.Monad(
    AuthHandler(..)
  , require
  , getConfig
  , getsConfig
  , runDB404
  , module Reexport
  ) where 

import Control.Monad.Except                 (ExceptT, MonadError)
import Control.Monad.Reader                 (MonadIO, MonadReader, ReaderT, ask, asks)
import Data.Monoid                          ((<>))
import Database.Persist.Postgresql          
import Servant                              

import qualified Data.ByteString.Lazy as BS 

import Servant.Server.Auth.Token.Config 
import Servant.Server.Auth.Token.Model 

import Servant.Server.Auth.Token.Error as Reexport

-- | This type represents the effects we want to have for our application.
-- We wrap the standard Servant monad with 'ReaderT Config', which gives us
-- access to the application configuration using the 'MonadReader'
-- interface's 'ask' function.
--
-- By encapsulating the effects in our newtype, we can add layers to the
-- monad stack without having to modify code that uses the current layout.
newtype AuthHandler a = AuthHandler { 
    runAuthHandler :: ReaderT AuthConfig (ExceptT ServantErr IO) a
  } deriving ( Functor, Applicative, Monad, MonadReader AuthConfig,
               MonadError ServantErr, MonadIO)

-- | If the value is 'Nothing', throw 400 response
require :: BS.ByteString -> Maybe a -> AuthHandler a
require info Nothing = throw400 $ info <> " is required"
require _ (Just a) = return a 

-- | Getting config from global state
getConfig :: AuthHandler AuthConfig 
getConfig = ask

-- | Getting config part from global state
getsConfig :: (AuthConfig -> a) -> AuthHandler a 
getsConfig = asks 

-- | Run RDBMS operation and throw 404 (not found) error if 
-- the second arg returns 'Nothing'
runDB404 ::  BS.ByteString -> SqlPersistT IO (Maybe a) -> AuthHandler a 
runDB404 info ma = do 
  a <- runDB ma
  case a of 
    Nothing -> throw404 $ "Cannot find " <> info 
    Just a' -> return a' 
