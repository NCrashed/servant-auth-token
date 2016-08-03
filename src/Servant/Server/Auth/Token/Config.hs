module Servant.Server.Auth.Token.Config(
    AuthConfig(..)
  , defaultAuthConfig
  ) where 

import Data.Text (Text)
import Data.Time 
import Database.Persist.Sql 
import Servant.Server 

-- | Configuration specific for authorisation system
data AuthConfig = AuthConfig {
  -- | Get database connection pool
    getPool :: ConnectionPool
  -- | For authorisation, defines amounts of seconds
  -- when token becomes invalid.
  , defaultExpire :: !NominalDiffTime
  -- | For password restore, defines amounts of seconds
  -- when restore code becomes invalid.
  , restoreExpire :: !NominalDiffTime
  -- | For authorisation, defines amount of hashing
  -- of new user passwords (should be greater or equal 14).
  -- The passwords hashed 2^strength times. It is needed to 
  -- prevent almost all kinds of bruteforce attacks, rainbow
  -- tables and dictionary attacks.
  , passwordsStrength :: !Int
  -- | Validates user password at registration / password change.
  -- 
  -- If the function returns 'Just', then a 400 error is raised with
  -- specified text.
  --
  -- Default value doesn't validate passwords at all.
  , passwordValidator :: !(Text -> Maybe Text)
  -- | Which template to use for password restoration
  , restoreEmailTemplate :: !Text
  -- | Title of email for password restoration
  , restoreEmailTitle :: !Text
  -- | From wich address we send restore email
  , restoreEmailSourceAddress :: !Text
  -- | Where to search mustache templates
  , templatesFolder :: !Text 
  -- | Transformation of errors produced by the auth server
  , servantErrorFormer :: !(ServantErr -> ServantErr)
  -- | SMPT server host
  , smptHost :: !Text 
  -- | SMPT server port
  , smptPort :: !Word 
  -- | SMPT server login and password
  , smptAuth :: !(Maybe (Text, Text))
  -- | Default size of page for pagination
  , defaultPageSize :: !Word 
  }

defaultAuthConfig :: ConnectionPool -> AuthConfig 
defaultAuthConfig pool = AuthConfig {
    getPool = pool
  , defaultExpire = fromIntegral (600 :: Int)
  , restoreExpire = fromIntegral (3*24*3600 :: Int) -- 3 days
  , passwordsStrength = 17
  , passwordValidator = const Nothing
  , restoreEmailTitle = "Restore password on fitclubs"
  , restoreEmailSourceAddress = "admin@fitclubs.teaspotstudio.ru"
  , restoreEmailTemplate = "email.mustache"
  , templatesFolder = "./templates"
  , servantErrorFormer = id
  , smptHost = "127.0.0.1"
  , smptPort = 25
  , smptAuth = Nothing
  , defaultPageSize = 50
  }