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
    AuthHandler
  , HasAuthConfig(..)
  , require
  , getConfig
  , getsConfig
  , guard404
  , module Reexport
  ) where

import Control.Monad.Except                 (MonadError)
import Control.Monad.IO.Class
import Data.Monoid                          ((<>))
import Servant

import qualified Data.ByteString.Lazy as BS

import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.Error as Reexport
import Servant.Server.Auth.Token.Model

-- | Context that is needed to run the auth server
type AuthHandler m = (HasAuthConfig m, MonadError ServerError m, MonadIO m, HasStorage m)

-- | If the value is 'Nothing', throw 400 response
require :: AuthHandler m => BS.ByteString -> Maybe a -> m a
require info Nothing = throw400 $ info <> " is required"
require _ (Just a) = return a

-- | Getting config from global state
getConfig :: AuthHandler m => m AuthConfig
getConfig = getAuthConfig

-- | Getting config part from global state
getsConfig :: AuthHandler m => (AuthConfig -> a) -> m a
getsConfig f = fmap f getAuthConfig

-- | Run RDBMS operation and throw 404 (not found) error if
-- the second arg returns 'Nothing'
guard404 :: AuthHandler m => BS.ByteString -> m (Maybe a) -> m a
guard404 info ma = do
  a <- ma
  case a of
    Nothing -> throw404 $ "Cannot find " <> info
    Just a' -> return a'
