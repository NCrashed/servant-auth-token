{-# LANGUAGE TemplateHaskell #-}
{-|
Module      : Servant.Server.Auth.Token.Error
Description : Utilities to wrap errors
Copyright   : (c) Anton Gushcha, 2016
License     : MIT
Maintainer  : ncrashed@gmail.com
Stability   : experimental
Portability : Portable
-}
module Servant.Server.Auth.Token.Error(
    throw400
  , throw401
  , throw404
  , throw409
  , throw500
  ) where

import Control.Monad.Except
import Servant.Server
import Servant.Server.Auth.Token.Config

import qualified Data.ByteString.Lazy as BS

-- | Prepare error response
makeBody :: HasAuthConfig m => ServerError -> m ServerError
makeBody e = do
  f <- fmap servantErrorFormer getAuthConfig
  return $ f e

-- | Wrappers to throw corresponding servant errors
throw400, throw401, throw404, throw409, throw500
  :: (MonadError ServerError m, HasAuthConfig m)
  => BS.ByteString -> m a
throw400 t = throwError =<< makeBody err400 { errBody = t }
throw401 t = throwError =<< makeBody err401 { errBody = t }
throw404 t = throwError =<< makeBody err404 { errBody = t }
throw409 t = throwError =<< makeBody err409 { errBody = t }
throw500 t = throwError =<< makeBody err500 { errBody = t }
