{-|
Module      : Servant.Server.Auth.Token.Common
Description : Internal utilities
Copyright   : (c) Anton Gushcha, 2016-2017
License     : MIT
Maintainer  : ncrashed@gmail.com
Stability   : experimental
Portability : Portable
-}
module Servant.Server.Auth.Token.Common where

import qualified Data.Text as T
import qualified Data.ByteString.Lazy.Char8 as BSL

-- | Helper to print a value to lazy bytestring
showb :: Show a => a -> BSL.ByteString
showb = BSL.pack . show

-- | Helper to print a value to text
showt :: Show a => a -> T.Text
showt = T.pack . show

-- | Do something when first value is 'Nothing'
whenNothing :: Applicative m => Maybe a -> m () -> m ()
whenNothing Nothing m = m
whenNothing (Just _) _ = pure ()

-- | Do something when first value is 'Just'
whenJust :: Applicative m => Maybe a -> (a -> m ()) -> m ()
whenJust Nothing _ = pure ()
whenJust (Just x) m = m x

class ConvertableKey a where
  -- | Shortcut to convert sql key
  fromKey :: Integral b => a -> b

  -- | Shortcut to convert sql key
  toKey :: Integral b => b -> a
