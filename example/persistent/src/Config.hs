module Config(
    ServerConfig(..)
  , readConfig
  ) where

import Control.Monad
import Control.Monad.IO.Class
import Data.Aeson
import Data.Text
import Data.Yaml.Config

-- | Startup configuration of server
data ServerConfig = ServerConfig {
  -- | Server host name
  serverHost                 :: !Text
  -- | Server port number
, serverPort                 :: !Int
  -- | DB host
, serverDBHost               :: !Text
  -- | DB port
, serverDBPort               :: !Int
  -- | DB user
, serverDBUser               :: !Text
  -- | DB user password
, serverDBPass               :: !Text
  -- | DB database
, serverDBBase               :: !Text
}

instance FromJSON ServerConfig where
  parseJSON (Object o) = ServerConfig
    <$> o .: "host"
    <*> o .: "port"
    <*> o .: "db-host"
    <*> o .: "db-port"
    <*> o .: "db-user"
    <*> o .: "db-pass"
    <*> o .: "db-base"
  parseJSON _ = mzero

readConfig :: MonadIO m => FilePath -> m ServerConfig
readConfig f = liftIO $ loadYamlSettings [f] [] useEnv
