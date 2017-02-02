{-|
Module      : Servant.Server.Auth.Token.Monad
Description : Helpers for pagination implementation
Copyright   : (c) Anton Gushcha, 2016
License     : MIT
Maintainer  : ncrashed@gmail.com
Stability   : experimental
Portability : Portable
-}
module Servant.Server.Auth.Token.Pagination(
    pagination
  ) where

import Data.Maybe

import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.Monad

import Servant.API.Auth.Token.Pagination

-- | Helper that implements pagination logic
pagination :: AuthHandler m
  => Maybe Page -- ^ Parameter of page
  -> Maybe PageSize -- ^ Parameter of page size
  -> (Page -> PageSize -> m a) -- ^ Handler
  -> m a
pagination pageParam pageSizeParam f = do
  ps <- getsConfig defaultPageSize
  let page = fromMaybe 0 pageParam
      pageSize = fromMaybe ps pageSizeParam
  f page pageSize
