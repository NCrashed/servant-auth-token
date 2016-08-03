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
import Data.Time.Clock
import Data.UUID
import Data.UUID.V4
import Database.Persist.Postgresql

import Servant.API.Auth.Token
import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.Model 
import Servant.Server.Auth.Token.Monad 

-- | Get current restore code for user or generate new
getRestoreCode :: UserImplId -> UTCTime -> SqlPersistT IO RestoreCode
getRestoreCode uid expire = do 
  t <- liftIO getCurrentTime
  mcode <- selectFirst [UserRestoreUser ==. uid, UserRestoreExpire >. t] [Desc UserRestoreExpire]
  case mcode of 
    Nothing -> do 
      code <- toText <$> liftIO nextRandom
      void $ insert UserRestore {
          userRestoreValue = code 
        , userRestoreUser = uid
        , userRestoreExpire = expire 
        }
      return code 
    Just code -> return $ userRestoreValue . entityVal $ code 

-- | Throw if the restore code isn't valid for given user, if valid, invalidates the code
guardRestoreCode :: UserImplId -> RestoreCode -> AuthHandler ()
guardRestoreCode uid code = do 
  t <- liftIO getCurrentTime
  mcode <- runDB $ selectFirst [UserRestoreUser ==. uid, UserRestoreValue ==. code
    , UserRestoreExpire >. t] [Desc UserRestoreExpire]
  case mcode of 
    Nothing -> throw400 "Invalid restore code"
    Just (Entity i rc) -> runDB $ replace i rc { userRestoreExpire = t }

-- | Send restore code to the user' email
sendRestoreCode :: RespUserInfo -> RestoreCode -> AuthHandler ()
sendRestoreCode user code = do 
  AuthConfig{..} <- getConfig
  liftIO $ restoreCodeSender user code 
