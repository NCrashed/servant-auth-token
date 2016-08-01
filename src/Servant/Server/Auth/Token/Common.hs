module Servant.Server.Auth.Token.Common where 

import Database.Persist.Sql 

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

-- | Shortcut to convert sql key
fromKey :: (Integral a, ToBackendKey SqlBackend record) 
  => Key record -> a 
fromKey = fromIntegral . fromSqlKey

-- | Shortcut to convert sql key
toKey :: (Integral a, ToBackendKey SqlBackend record) 
  => a -> Key record 
toKey = toSqlKey . fromIntegral