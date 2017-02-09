{-# OPTIONS_GHC -fno-warn-redundant-constraints #-}
module DB where

import Data.SafeCopy

import Servant.Server.Auth.Token.Acid.Schema as A

-- | Application global state for acid-state
data DB = DB {
  dbAuth :: A.Model -- ^ Storage for Auth state
, dbCustom :: () -- ^ Demo of custom state
}

-- | Generation of inital state
newDB :: DB
newDB = DB {
    dbAuth = A.newModel
  , dbCustom = ()
  }

instance HasModelRead DB where
  askModel = dbAuth

instance HasModelWrite DB where
  putModel db m = db { dbAuth = m }

deriveSafeCopy 0 'base ''DB

A.deriveQueries ''DB
A.makeModelAcidic ''DB
