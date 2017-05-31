{-# LANGUAGE DefaultSignatures, RecordWildCards #-}
module Servant.Server.Auth.Token.Persistent.Schema where

import Data.Text
import Data.Time
import Database.Persist.Sql (Key, SqlBackend, ToBackendKey, fromSqlKey,
                             toSqlKey)
import Database.Persist.TH
import GHC.Generics         (Generic)

import           Servant.API.Auth.Token
import           Servant.Server.Auth.Token.Common (ConvertableKey, fromKey,
                                                   toKey)
import qualified Servant.Server.Auth.Token.Model  as M

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
  default convertTo :: (ToBackendKey SqlBackend r, a ~ Key r, ConvertableKey b) => b -> a
  convertTo = toSqlKey . fromKey

  -- | Convert from internal representation
  convertFrom :: a -> b
  default convertFrom :: (ToBackendKey SqlBackend r, a ~ Key r, ConvertableKey b) => a -> b
  convertFrom = toKey . fromSqlKey

instance ConvertStorage UserImpl M.UserImpl where
  convertTo M.UserImpl{..} =
    UserImpl { userImplLogin    = userImplLogin
             , userImplPassword = userImplPassword
             , userImplEmail    = userImplEmail
             }

  convertFrom UserImpl{..} =
    M.UserImpl { userImplLogin    = userImplLogin
               , userImplPassword = userImplPassword
               , userImplEmail    = userImplEmail
               }

instance ConvertStorage UserPerm M.UserPerm where
  convertTo M.UserPerm{..} =
    UserPerm { userPermUser       = convertTo userPermUser
             , userPermPermission = userPermPermission
             }

  convertFrom UserPerm{..} =
    M.UserPerm { userPermUser       = convertFrom userPermUser
               , userPermPermission = userPermPermission
               }

instance ConvertStorage AuthToken M.AuthToken where
  convertTo M.AuthToken{..} =
    AuthToken { authTokenValue  = authTokenValue
              , authTokenUser   = convertTo authTokenUser
              , authTokenExpire = authTokenExpire
              }

  convertFrom AuthToken{..} =
    M.AuthToken { authTokenValue  = authTokenValue
                , authTokenUser   = convertFrom authTokenUser
                , authTokenExpire = authTokenExpire
                }

instance ConvertStorage UserRestore M.UserRestore where
  convertTo M.UserRestore{..} =
    UserRestore { userRestoreValue  = userRestoreValue
                , userRestoreUser   = convertTo userRestoreUser
                , userRestoreExpire = userRestoreExpire
                }

  convertFrom UserRestore{..} =
    M.UserRestore { userRestoreValue  = userRestoreValue
                  , userRestoreUser   = convertFrom userRestoreUser
                  , userRestoreExpire = userRestoreExpire
                  }

instance ConvertStorage UserSingleUseCode M.UserSingleUseCode where
  convertTo M.UserSingleUseCode{..} =
    UserSingleUseCode { userSingleUseCodeValue  = userSingleUseCodeValue
                      , userSingleUseCodeUser   = convertTo userSingleUseCodeUser
                      , userSingleUseCodeExpire = userSingleUseCodeExpire
                      , userSingleUseCodeUsed   = userSingleUseCodeUsed
                      }

  convertFrom UserSingleUseCode{..} =
    M.UserSingleUseCode { userSingleUseCodeValue  = userSingleUseCodeValue
                        , userSingleUseCodeUser   = convertFrom userSingleUseCodeUser
                        , userSingleUseCodeExpire = userSingleUseCodeExpire
                        , userSingleUseCodeUsed   = userSingleUseCodeUsed
                        }

instance ConvertStorage AuthUserGroup M.AuthUserGroup where
  convertTo M.AuthUserGroup{..} =
    AuthUserGroup { authUserGroupName   = authUserGroupName
                  , authUserGroupParent = convertTo <$> authUserGroupParent
                  }

  convertFrom AuthUserGroup{..} =
    M.AuthUserGroup { authUserGroupName   = authUserGroupName
                    , authUserGroupParent = convertFrom <$> authUserGroupParent
                    }

instance ConvertStorage AuthUserGroupUsers M.AuthUserGroupUsers where
  convertTo M.AuthUserGroupUsers{..} =
    AuthUserGroupUsers { authUserGroupUsersGroup = convertTo authUserGroupUsersGroup
                       , authUserGroupUsersUser  = convertTo authUserGroupUsersUser
                       }

  convertFrom AuthUserGroupUsers{..} =
    M.AuthUserGroupUsers { authUserGroupUsersGroup = convertFrom authUserGroupUsersGroup
                         , authUserGroupUsersUser  = convertFrom authUserGroupUsersUser
                         }

instance ConvertStorage AuthUserGroupPerms M.AuthUserGroupPerms where
  convertTo M.AuthUserGroupPerms{..} =
    AuthUserGroupPerms { authUserGroupPermsGroup      = convertTo authUserGroupPermsGroup
                       , authUserGroupPermsPermission = authUserGroupPermsPermission
                       }

  convertFrom AuthUserGroupPerms{..} =
    M.AuthUserGroupPerms { authUserGroupPermsGroup      = convertFrom authUserGroupPermsGroup
                         , authUserGroupPermsPermission = authUserGroupPermsPermission
                         }

instance ConvertStorage UserImplId M.UserImplId
instance ConvertStorage UserPermId M.UserPermId
instance ConvertStorage AuthTokenId M.AuthTokenId
instance ConvertStorage UserRestoreId M.UserRestoreId
instance ConvertStorage UserSingleUseCodeId M.UserSingleUseCodeId
instance ConvertStorage AuthUserGroupId M.AuthUserGroupId
instance ConvertStorage AuthUserGroupUsersId M.AuthUserGroupUsersId
instance ConvertStorage AuthUserGroupPermsId M.AuthUserGroupPermsId
