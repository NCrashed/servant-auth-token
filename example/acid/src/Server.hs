module Server(
  -- * Server config
    ServerConfig(..)
  , readConfig
  -- * Server environment
  , ServerEnv
  , newServerEnv
  -- * Execution of server
  , exampleServerApp
  , runExampleServer
  ) where

import Control.Monad.IO.Class
import Control.Monad.Logger
import Data.Aeson.Unit
import Data.Aeson.WithField
import Data.Proxy
import Network.Wai
import Network.Wai.Handler.Warp
import Network.Wai.Middleware.RequestLogger
import Servant.API 
import Servant.API.Auth.Token
import Servant.Server
import Servant.Server.Auth.Token

import API
import Config
import Monad

-- | Enter infinite loop of processing requests for pdf-master-server.
--
-- Starts new Warp server with initialised threads for serving the master server.
runExampleServer :: MonadIO m => ServerConfig -> m ()
runExampleServer config = liftIO $ do
  env <- newServerEnv config
  liftIO $ run (serverPort config) $ logStdoutDev $ exampleServerApp env

-- | WAI application of server
exampleServerApp :: ServerEnv -> Application
exampleServerApp e = serve api apiImpl
  where
    api = Proxy :: Proxy ExampleAPI
    apiImpl = hoistServer api (runServerM e) exampleServer

-- | Implementation of main server API
exampleServer :: ServerT ExampleAPI ServerM
exampleServer = testEndpoint
  -- Pass though requests directly to the library in these endpoints
  :<|> authSigninPostProxy
  :<|> authTouchProxy
  :<|> authSignoutProxy

testEndpoint :: MToken' '["test-permission"] -> ServerM ()
testEndpoint token = do
  runAuth $ guardAuthToken token
  $logInfo "testEndpoint"
  return ()

authSigninPostProxy :: AuthSigninPostBody -> ServerM (OnlyField "token" SimpleToken)
authSigninPostProxy AuthSigninPostBody{..} = runAuth $ authSignin (Just authSigninBodyLogin) (Just authSigninBodyPassword) authSigninBodySeconds

authTouchProxy :: Maybe Seconds -> MToken' '[] -> ServerM Unit
authTouchProxy mexpire token = runAuth $ authTouch mexpire token

authSignoutProxy :: MToken' '[] -> ServerM Unit
authSignoutProxy mtoken = runAuth $ authSignout mtoken
