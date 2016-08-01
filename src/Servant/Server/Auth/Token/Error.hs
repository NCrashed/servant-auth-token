{-# LANGUAGE TemplateHaskell #-}
module Servant.Server.Auth.Token.Error(
    throw400
  , throw401
  , throw404
  , throw409
  , throw500
  ) where 

import Control.Monad.Except
import Control.Monad.Reader.Class
import Servant.Server
import Servant.Server.Auth.Token.Config

import qualified Data.ByteString.Lazy as BS 

-- | Prepare error response
makeBody :: MonadReader AuthConfig m => ServantErr -> m ServantErr
makeBody e = do
  f <- asks servantErrorFormer
  return $ f e

throw400, throw401, throw404, throw409, throw500 
  :: (MonadError ServantErr m, MonadReader AuthConfig m) 
  => BS.ByteString -> m a
throw400 t = throwError =<< makeBody err400 { errBody = t }
throw401 t = throwError =<< makeBody err401 { errBody = t }
throw404 t = throwError =<< makeBody err404 { errBody = t }
throw409 t = throwError =<< makeBody err409 { errBody = t }
throw500 t = throwError =<< makeBody err500 { errBody = t }