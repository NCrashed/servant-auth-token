{-# language DataKinds #-}
{-# language MultiParamTypeClasses #-}
{-# language FlexibleContexts #-}
{-# language FlexibleInstances #-}
{-# language TypeFamilies #-}
{-# language TypeOperators #-}
{-# language KindSignatures #-}
{-# language RecordWildCards #-}
{-# language RankNTypes #-}

module Servant.Server.Auth.Token.Combinator
  ( AuthPerm
  , AuthAction(..)
  ) where

import Control.Monad.IO.Class
import GHC.TypeLits (Symbol)
import Data.Proxy
import Network.Wai (Request, requestHeaders)
import Servant.API
import Servant.Server
import Servant.Server.Internal (Delayed(..), DelayedIO(..), withRequest,
                                delayedFailFatal)
import Servant.API.Auth.Token  (SimpleToken(..), Permission(..),
                                Token(..), PlainPerms, PermsList(..))
import Web.HttpApiData         (parseHeaderMaybe)
import qualified Data.Text as T


-- | An authentication combinator.
--
-- TODO maybe move in the servant-auth-api library
data AuthPerm (perms :: [Symbol])

-- | An authentication handler.
newtype AuthAction = AuthAction
  { unAuthAction :: Maybe SimpleToken -> [Permission] -> Handler () }

instance ( HasServer api context
         , PermsList (PlainPerms perms)
         , HasContextEntry context AuthAction
         )
  => HasServer (AuthPerm perms :> api) context where

  type ServerT (AuthPerm perms :> api) m = ServerT api m

  route Proxy context subserver
    = route (Proxy :: Proxy api) context
      (subserver `addAuthPermCheck` withRequest (authCheck (Proxy :: Proxy perms)))
      where
        authHandler :: Proxy perms -> Request -> Handler ()
        authHandler pperms req =
          let authAction = getContextEntry context
              mHeader = parseHeaderMaybe
                  =<< lookup "Authorization" (requestHeaders req)
          in unAuthAction authAction mHeader
              $ unliftPerms (Proxy :: Proxy (PlainPerms perms))

        authCheck :: Proxy perms -> Request -> DelayedIO ()
        authCheck pperms = (>>= either delayedFailFatal pure) . liftIO
                      . runHandler . authHandler pperms

        addAuthPermCheck :: Delayed env b -> DelayedIO a -> Delayed env b
        addAuthPermCheck Delayed{..} new = Delayed
          { authD   = (,) <$> authD <*> new
          , serverD = \ c p h (y, v) b req -> serverD c p h y b req
          , ..
          }

