module Servant.Server.Auth.Token.Pagination(
    pagination
  ) where 

import Data.Maybe 

import Servant.Server.Auth.Token.Config 
import Servant.Server.Auth.Token.Monad 

import Servant.API.Auth.Token.Pagination

-- | Helper that implements pagination logic
pagination :: Maybe Page -- ^ Parameter of page
  -> Maybe PageSize -- ^ Parameter of page size
  -> (Page -> PageSize -> AuthHandler a) -- ^ Handler
  -> AuthHandler a
pagination pageParam pageSizeParam f = do 
  ps <- getsConfig defaultPageSize
  let page = fromMaybe 0 pageParam 
      pageSize = fromMaybe ps pageSizeParam
  f page pageSize 
