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
  serverHost   :: !Text
  -- | Server port number
, serverPort   :: !Int
  -- | Server db location
, serverDbPath :: !Text
}

instance FromJSON ServerConfig where
  parseJSON (Object o) = ServerConfig
    <$> o .: "host"
    <*> o .: "port"
    <*> o .: "db"
  parseJSON _ = mzero

readConfig :: MonadIO m => FilePath -> m ServerConfig
readConfig f = liftIO $ loadYamlSettings [f] [] useEnv
