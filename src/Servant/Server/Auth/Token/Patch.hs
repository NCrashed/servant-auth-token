{-|
Module      : Servant.Server.Auth.Token.Patch
Description : Helpers for patching entities
Copyright   : (c) Anton Gushcha, 2016
License     : MIT
Maintainer  : ncrashed@gmail.com
Stability   : experimental
Portability : Portable
-}
module Servant.Server.Auth.Token.Patch(
    withPatch
  , withPatch'
  , withNullPatch
  , withNullPatch'
  ) where 

-- | Helper for implementation of 'HasPatch'
withPatch :: Monad m => Maybe a -> (a -> b -> m b) -> b -> m b 
withPatch v f b = case v of 
  Nothing -> return b 
  Just a -> f a b
{-# INLINE withPatch #-}

-- | Helper for implementation of 'HasPatch'
withPatch' :: Maybe a -> (a -> b -> b) -> b -> b 
withPatch' v f b = case v of 
  Nothing -> b 
  Just a -> f a b
{-# INLINE withPatch' #-}

-- | Helper to implement patch with nullable flag
withNullPatch :: Monad m
  => Maybe Bool -- ^ If this is 'Just true' then execute following updater
  -> (b -> m b) -- ^ Updater when previous value is 'Just true'
  -> Maybe a -- ^ If the value is 'Just' and the first parameter is 'Nothing' then execute following updater
  -> (a -> b -> m b) -- ^ Main updater
  -> b -> m b
withNullPatch mnull nullify ma updater b = case mnull of 
  Just True -> nullify b 
  _ -> withPatch ma updater b
{-# INLINE withNullPatch #-}

-- | Helper to implement patch with nullable flag
withNullPatch' :: Maybe Bool -- ^ If this is 'Just true' then execute following updater
  -> (b -> b) -- ^ Updater when previous value is 'Just true'
  -> Maybe a -- ^ If the value is 'Just' and the first parameter is 'Nothing' then execute following updater
  -> (a -> b -> b) -- ^ Main updater
  -> b -> b
withNullPatch' mnull nullify ma updater b = case mnull of 
  Just True -> nullify b 
  _ -> withPatch' ma updater b
{-# INLINE withNullPatch' #-}