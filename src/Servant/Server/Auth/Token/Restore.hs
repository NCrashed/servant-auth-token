module Servant.Server.Auth.Token.Restore(
    getRestoreCode
  , guardRestoreCode
  , sendRestoreCode
  ) where 

import Control.Monad 
import Control.Monad.IO.Class 
import Data.Monoid
import Data.Text (unpack)
import Data.Time.Clock
import Data.Time.Format
import Data.UUID
import Data.UUID.V4
import Database.Persist.Postgresql
import Network.Mail.SMTP
import Text.Mustache as M

import qualified Data.Text.Lazy as T 

import Servant.API.Auth.Token
import Servant.Server.Auth.Token.Common
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
sendRestoreCode :: UserImpl -> RestoreCode -> AuthHandler ()
sendRestoreCode UserImpl{..} code = do 
  AuthConfig{..} <- getConfig
  t <- liftIO getCurrentTime
  res <- liftIO $ automaticCompile [unpack templatesFolder] (unpack restoreEmailTemplate)
  case res of
    Left er -> throw500 $ "Email template: " <> showb er
    Right tmp -> do
      let body = substituteValue tmp $ M.object [
              "code" ~> code
            , "login" ~> userImplLogin
            , "time" ~> formatTime defaultTimeLocale "%Y-%m-%dT%H:%M:%S" t 
            ]
      let email = simpleMail
            (Address Nothing restoreEmailSourceAddress)
            [Address Nothing userImplEmail]
            [] -- cc
            [] -- bcc
            restoreEmailTitle
            [plainTextPart $ T.fromStrict body]

      liftIO $ case smptAuth of 
        Nothing -> sendMail' (unpack smptHost) (fromIntegral smptPort) email 
        Just (smptUser, smptPass) -> sendMailWithLogin' (unpack smptHost) (fromIntegral smptPort) 
          (unpack smptUser) (unpack smptPass) email 