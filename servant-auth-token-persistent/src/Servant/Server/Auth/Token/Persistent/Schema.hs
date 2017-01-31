{-# LANGUAGE MagicHash #-}
module Servant.Server.Auth.Token.Persistent.Schema where

import Data.Text
import Data.Time
import Database.Persist.TH
import GHC.Generics
import GHC.Prim

import Servant.API.Auth.Token

import qualified Servant.Server.Auth.Token.Model as M

share [mkPersist sqlSettings
     , mkDeleteCascade sqlSettings
     , mkMigrate "migrateAll"] [persistLowerCase|
UserImpl
  login       Login
  password    Password     -- encrypted with salt
  email       Email
  UniqueLogin login
  deriving Generic Show
UserPerm
  user        UserImplId
  permission  Permission
  deriving Generic Show
AuthToken
  value       SimpleToken
  user        UserImplId
  expire      UTCTime
  deriving Generic Show
UserRestore
  value       RestoreCode
  user        UserImplId
  expire      UTCTime
  deriving Generic Show
UserSingleUseCode
  value     SingleUseCode
  user      UserImplId
  expire    UTCTime Maybe -- Nothing is code that never expires
  used      UTCTime Maybe
  deriving Generic Show
AuthUserGroup
  name        Text
  parent      AuthUserGroupId Maybe
  deriving Generic Show
AuthUserGroupUsers
  group       AuthUserGroupId
  user        UserImplId
  deriving Generic Show
AuthUserGroupPerms
  group       AuthUserGroupId
  permission  Permission
  deriving Generic Show
|]

-- | Defines way to convert from persistent struct to model struct and vice versa.
--
-- Warning: default implementation is done via 'unsafeCoerce#', so make sure that
-- structure of 'a' and 'b' is completely identical.
class ConvertStorage a b | a -> b, b -> a where
  -- | Convert to internal representation
  convertTo   :: b -> a
  convertTo = unsafeCoerce#
  -- | Convert from internal representation
  convertFrom :: a -> b
  convertFrom = unsafeCoerce#

instance ConvertStorage UserImpl M.UserImpl
instance ConvertStorage UserPerm M.UserPerm
instance ConvertStorage AuthToken M.AuthToken
instance ConvertStorage UserRestore M.UserRestore
instance ConvertStorage UserSingleUseCode M.UserSingleUseCode
instance ConvertStorage AuthUserGroup M.AuthUserGroup
instance ConvertStorage AuthUserGroupUsers M.AuthUserGroupUsers
instance ConvertStorage AuthUserGroupPerms M.AuthUserGroupPerms

instance ConvertStorage UserImplId M.UserImplId
instance ConvertStorage UserPermId M.UserPermId
instance ConvertStorage AuthTokenId M.AuthTokenId
instance ConvertStorage UserRestoreId M.UserRestoreId
instance ConvertStorage UserSingleUseCodeId M.UserSingleUseCodeId
instance ConvertStorage AuthUserGroupId M.AuthUserGroupId
instance ConvertStorage AuthUserGroupUsersId M.AuthUserGroupUsersId
instance ConvertStorage AuthUserGroupPermsId M.AuthUserGroupPermsId
