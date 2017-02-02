{-|
Module      : Servant.Server.Auth.Token.Restore
Description : Operations with restore codes
Copyright   : (c) Anton Gushcha, 2016
License     : MIT
Maintainer  : ncrashed@gmail.com
Stability   : experimental
Portability : Portable
-}
module Servant.Server.Auth.Token.Restore(
    getRestoreCode
  , guardRestoreCode
  , sendRestoreCode
  ) where

import Control.Monad
import Control.Monad.IO.Class
import Data.Aeson.WithField
import Data.Time.Clock

import Servant.API.Auth.Token
import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.Model
import Servant.Server.Auth.Token.Monad

-- | Get current restore code for user or generate new
getRestoreCode :: HasStorage m => IO RestoreCode -> UserImplId -> UTCTime -> m RestoreCode
getRestoreCode generator uid expire = do
  t <- liftIO getCurrentTime
  mcode <- selectLastRestoreCode uid t
  case mcode of
    Nothing -> do
      code <- liftIO generator
      void $ insertUserRestore UserRestore {
          userRestoreValue = code
        , userRestoreUser = uid
        , userRestoreExpire = expire
        }
      return code
    Just code -> return $ userRestoreValue . (\(WithField _ v) -> v) $ code

-- | Throw if the restore code isn't valid for given user, if valid, invalidates the code
guardRestoreCode :: AuthHandler m => UserImplId -> RestoreCode -> m ()
guardRestoreCode uid code = do
  t <- liftIO getCurrentTime
  mcode <- findRestoreCode uid code t
  case mcode of
    Nothing -> throw400 "Invalid restore code"
    Just (WithField i rc) -> replaceRestoreCode i rc { userRestoreExpire = t }

-- | Send restore code to the user' email
sendRestoreCode :: AuthHandler m => RespUserInfo -> RestoreCode -> m ()
sendRestoreCode user code = do
  AuthConfig{..} <- getConfig
  liftIO $ restoreCodeSender user code
