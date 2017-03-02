module Main where

import Data.Monoid
import Options.Applicative

import Server

-- | Argument line options
data Options = Options {
  -- | Path to config, if not set, the app will not start
  configPath :: FilePath
}

-- | Command line parser
optionsParser :: Parser Options
optionsParser = Options
  <$> strOption (
         long "conf"
      <> metavar "CONFIG"
      <> help "Path to configuration file"
    )

-- | Execute server with given options
runServer :: Options -> IO ()
runServer Options{..} = do
  cfg <- readConfig configPath
  runExampleServer cfg

main :: IO ()
main = execParser opts >>= runServer
  where
    opts = info (helper <*> optionsParser)
      ( fullDesc
     <> progDesc "Example server for servant-auth-token"
     <> header "servant-auth-token-example-persistent - example of integration of servant token auth library" )
