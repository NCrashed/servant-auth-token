{-# OPTIONS_GHC -fno-warn-orphans #-}
module Servant.Server.Auth.Token.Acid.Schema where

import Control.Monad.Reader
import Control.Monad.State
import Data.Acid
import Data.Aeson.WithField
import Data.Int
import Data.List (sortBy)
import Data.Map.Strict (Map)
import Data.Ord
import Data.SafeCopy
import Data.Text (Text)
import Data.Time
import Safe

import Servant.API.Auth.Token
import Servant.API.Auth.Token.Pagination
import Servant.Server.Auth.Token.Common
import Servant.Server.Auth.Token.Model(
    UserImplId
  , UserImpl(..)
  , UserPermId
  , UserPerm(..)
  , AuthTokenId
  , AuthToken(..)
  , UserRestoreId
  , UserRestore(..)
  , UserSingleUseCodeId
  , UserSingleUseCode(..)
  , AuthUserGroupId
  , AuthUserGroup(..)
  , AuthUserGroupUsersId
  , AuthUserGroupUsers(..)
  , AuthUserGroupPermsId
  , AuthUserGroupPerms(..)
  )

import qualified Data.Map.Strict as M
import qualified Data.Foldable as F

-- | Holds all data for auth server in acid-state container
data Model = Model {
  -- | Holds users by id
  modelUsers                    :: !(Map UserImplId UserImpl)
  -- | Holds users by login (same content as 'modelUsers')
, modelUsersByLogin             :: !(Map Login (WithId UserImplId UserImpl))
  -- | Holds 'UserPerm'
, modelUserPerms                :: !(Map UserPermId UserPerm)
  -- | Holds 'AuthToken'
, modelAuthTokens               :: !(Map AuthTokenId AuthToken)
  -- | Holds 'UserRestore'
, modelUserRestores             :: !(Map UserRestoreId UserRestore)
  -- | Holds 'UserSingleUseCode'
, modelUserSingleUseCodes       :: !(Map UserSingleUseCodeId UserSingleUseCode)
  -- | Holds 'AuthUserGroup'
, modelAuthUserGroups           :: !(Map AuthUserGroupId AuthUserGroup)
  -- | Holds 'AuthUserGroupUsers'
, modelAuthUserGroupUsers       :: !(Map AuthUserGroupUsersId AuthUserGroupUsers)
  -- | Holds 'AuthUserGroupPerms'
, modelAuthUserGroupPerms       :: !(Map AuthUserGroupPermsId AuthUserGroupPerms)
  -- | Holds next id for entities
, modelNextUserImplId           :: !Int64
-- | Holds next id for entities
, modelNextUserPermId           :: !Int64
-- | Holds next id for entities
, modelNextAuthTokenId          :: !Int64
-- | Holds next id for entities
, modelNextUserRestoreId        :: !Int64
-- | Holds next id for entities
, modelNextUserSingleUseCodeId  :: !Int64
-- | Holds next id for entities
, modelNextAuthUserGroupId      :: !Int64
-- | Holds next id for entities
, modelNextAuthUserGroupUserId  :: !Int64
-- | Holds next id for entities
, modelNextAuthUserGroupPermId  :: !Int64
}

-- | Defines empty model for new database
newModel :: Model
newModel = Model {
    modelUsers = mempty
  , modelUsersByLogin = mempty
  , modelUserPerms = mempty
  , modelAuthTokens = mempty
  , modelUserRestores = mempty
  , modelUserSingleUseCodes = mempty
  , modelAuthUserGroups = mempty
  , modelAuthUserGroupUsers = mempty
  , modelAuthUserGroupPerms = mempty
  , modelNextUserImplId = 0
  , modelNextUserPermId = 0
  , modelNextAuthTokenId = 0
  , modelNextUserRestoreId = 0
  , modelNextUserSingleUseCodeId = 0
  , modelNextAuthUserGroupId = 0
  , modelNextAuthUserGroupUserId = 0
  , modelNextAuthUserGroupPermId = 0
  }

-- | Getting user from storage
getUserImpl :: UserImplId -> Query Model (Maybe UserImpl)
getUserImpl i = M.lookup i <$> asks modelUsers

-- | Getting user from storage by login
getUserImplByLogin :: Login -> Query Model (Maybe (WithId UserImplId UserImpl))
getUserImplByLogin l = M.lookup l <$> asks modelUsersByLogin

-- | Helper to get page from map
getPagedList :: Ord i => Page -> PageSize -> Map i a -> ([WithId i a], Word)
getPagedList p s m = (uncurry WithField <$> es, fromIntegral $ F.length m)
  where
    es = take (fromIntegral s) . drop (fromIntegral $ p * s) . sortBy (comparing fst) . M.toList $ m

-- | Get paged list of users and total count of users
listUsersPaged :: Page -> PageSize -> Query Model ([WithId UserImplId UserImpl], Word)
listUsersPaged p s = getPagedList p s <$> asks modelUsers

-- | Get user permissions, ascending by tag
getUserImplPermissions :: UserImplId -> Query Model [WithId UserPermId UserPerm]
getUserImplPermissions i = fmap (uncurry WithField) . M.toList . M.filter ((i ==) . userPermUser) <$> asks modelUserPerms

-- | Delete user permissions
deleteUserPermissions :: UserImplId -> Update Model ()
deleteUserPermissions i = modify' $ \m -> m { modelUserPerms = f $ modelUserPerms m }
  where
    f m = m `M.difference` M.filter ((i ==) . userPermUser) m

-- | Insertion of new user permission
insertUserPerm :: UserPerm -> Update Model UserPermId
insertUserPerm p = do
  m <- get
  let
    i = toKey $ modelNextUserPermId m
    perms = M.insert i p . modelUserPerms $ m
    m' = m { modelUserPerms = perms, modelNextUserPermId = modelNextUserPermId m + 1 }
  m' `seq` put m'
  return i

-- | Insertion of new user
insertUserImpl :: UserImpl -> Update Model UserImplId
insertUserImpl v = do
  m <- get
  let
    i = toKey $ modelNextUserImplId m
    vals = M.insert i v . modelUsers $ m
    vals' = M.insert (userImplLogin v) (WithField i v) . modelUsersByLogin $ m
    m' = m { modelUsers = vals, modelUsersByLogin = vals', modelNextUserImplId = modelNextUserImplId m + 1 }
  m' `seq` put m'
  return i

-- | Replace user with new value
replaceUserImpl :: UserImplId -> UserImpl -> Update Model ()
replaceUserImpl i v = modify' $ \m -> m {
    modelUsers = M.insert i v . modelUsers $ m
  , modelUsersByLogin = M.insert (userImplLogin v) (WithField i v) . modelUsersByLogin $ m
  }

-- | Delete user by id
deleteUserImpl :: UserImplId -> Update Model ()
deleteUserImpl i = do
  deleteUserPermissions i
  modify' $ \m -> case M.lookup i . modelUsers $ m of
    Nothing -> m
    Just UserImpl{..} -> m {
        modelUsers = M.delete i . modelUsers $ m
      , modelUsersByLogin = M.delete userImplLogin . modelUsersByLogin $ m
      }

-- | Check whether the user has particular permission
hasPerm :: UserImplId -> Permission -> Query Model Bool
hasPerm i p = (> 0) . F.length . M.filter (\UserPerm{..} -> userPermUser == i && userPermPermission == p) <$> asks modelUserPerms

-- | Get any user with given permission
getFirstUserByPerm :: Permission -> Query Model (Maybe (WithId UserImplId UserImpl))
getFirstUserByPerm perm = do
  m <- asks modelUserPerms
  case M.toList . M.filter (\UserPerm{..} -> userPermPermission == perm) $ m of
    [] -> return Nothing
    ((_, UserPerm{..}) : _) -> fmap (WithField userPermUser) <$> getUserImpl userPermUser

-- | Select user groups and sort them by ascending name
selectUserImplGroups :: UserImplId -> Query Model [WithId AuthUserGroupUsersId AuthUserGroupUsers]
selectUserImplGroups i = fmap (uncurry WithField) . M.toList . M.filter ((i ==) . authUserGroupUsersUser) <$> asks modelAuthUserGroupUsers

-- | Remove user from all groups
clearUserImplGroups :: UserImplId -> Update Model ()
clearUserImplGroups i = modify' $ \m -> m { modelAuthUserGroupUsers = f $ modelAuthUserGroupUsers m }
  where
    f m = m `M.difference` M.filter ((i ==) . authUserGroupUsersUser) m

-- | Add new user group
insertAuthUserGroup :: AuthUserGroup -> Update Model AuthUserGroupId
insertAuthUserGroup v = do
  m <- get
  let
    i = toKey $ modelNextAuthUserGroupId m
    vals = M.insert i v . modelAuthUserGroups $ m
    m' = m { modelAuthUserGroups = vals, modelNextAuthUserGroupId = modelNextAuthUserGroupId m + 1 }
  m' `seq` put m'
  return i

-- | Add user to given group
insertAuthUserGroupUsers :: AuthUserGroupUsers -> Update Model AuthUserGroupUsersId
insertAuthUserGroupUsers v = do
  m <- get
  let
    i = toKey $ modelNextAuthUserGroupUserId m
    vals = M.insert i v . modelAuthUserGroupUsers $ m
    m' = m { modelAuthUserGroupUsers = vals, modelNextAuthUserGroupUserId = modelNextAuthUserGroupUserId m + 1 }
  m' `seq` put m'
  return i

-- | Add permission to given group
insertAuthUserGroupPerms :: AuthUserGroupPerms -> Update Model AuthUserGroupPermsId
insertAuthUserGroupPerms v = do
  m <- get
  let
    i = toKey $ modelNextAuthUserGroupPermId m
    vals = M.insert i v . modelAuthUserGroupPerms $ m
    m' = m { modelAuthUserGroupPerms = vals, modelNextAuthUserGroupPermId = modelNextAuthUserGroupPermId m + 1 }
  m' `seq` put m'
  return i

-- | Find user group by id
getAuthUserGroup :: AuthUserGroupId -> Query Model (Maybe AuthUserGroup)
getAuthUserGroup i = M.lookup i <$> asks modelAuthUserGroups

-- | Get list of permissions of given group
listAuthUserGroupPermissions :: AuthUserGroupId -> Query Model [WithId AuthUserGroupPermsId AuthUserGroupPerms]
listAuthUserGroupPermissions i = fmap (uncurry WithField) . M.toList . M.filter ((i ==) . authUserGroupPermsGroup) <$> asks modelAuthUserGroupPerms

-- | Get list of all users of the group
listAuthUserGroupUsers :: AuthUserGroupId -> Query Model [WithId AuthUserGroupUsersId AuthUserGroupUsers]
listAuthUserGroupUsers i = fmap (uncurry WithField) . M.toList . M.filter ((i ==) . authUserGroupUsersGroup) <$> asks modelAuthUserGroupUsers

-- | Replace record of user group
replaceAuthUserGroup :: AuthUserGroupId -> AuthUserGroup -> Update Model ()
replaceAuthUserGroup i v = modify' $ \m -> m { modelAuthUserGroups = M.insert i v $ modelAuthUserGroups m }

-- | Remove all users from group
clearAuthUserGroupUsers :: AuthUserGroupId -> Update Model ()
clearAuthUserGroupUsers i = modify' $ \m -> m { modelAuthUserGroupUsers = f $ modelAuthUserGroupUsers m }
  where
    f m = m `M.difference` M.filter ((i ==) . authUserGroupUsersGroup) m

-- | Remove all permissions from group
clearAuthUserGroupPerms :: AuthUserGroupId -> Update Model ()
clearAuthUserGroupPerms i = modify' $ \m -> m { modelAuthUserGroupPerms = f $ modelAuthUserGroupPerms m }
  where
    f m = m `M.difference` M.filter ((i ==) . authUserGroupPermsGroup) m

-- | Delete user group from storage
deleteAuthUserGroup :: AuthUserGroupId -> Update Model ()
deleteAuthUserGroup i = do
  clearAuthUserGroupUsers i
  clearAuthUserGroupPerms i
  modify' $ \m -> m { modelAuthUserGroups = M.delete i $ modelAuthUserGroups m }

-- | Get paged list of user groups with total count
listGroupsPaged :: Page -> PageSize -> Query Model ([WithId AuthUserGroupId AuthUserGroup], Word)
listGroupsPaged p s = getPagedList p s <$> asks modelAuthUserGroups

-- | Set group name
setAuthUserGroupName :: AuthUserGroupId -> Text -> Update Model ()
setAuthUserGroupName i n = modify' $ \m -> m { modelAuthUserGroups = M.adjust (\v -> v { authUserGroupName = n }) i $ modelAuthUserGroups m }

-- | Set group parent
setAuthUserGroupParent :: AuthUserGroupId -> Maybe AuthUserGroupId -> Update Model ()
setAuthUserGroupParent i p = modify' $ \m -> m { modelAuthUserGroups = M.adjust (\v -> v { authUserGroupParent = p }) i $ modelAuthUserGroups m }

-- | Add new single use code
insertSingleUseCode :: UserSingleUseCode -> Update Model UserSingleUseCodeId
insertSingleUseCode v = do
  m <- get
  let
    i = toKey $ modelNextUserSingleUseCodeId m
    vals = M.insert i v . modelUserSingleUseCodes $ m
    m' = m { modelUserSingleUseCodes = vals, modelNextUserSingleUseCodeId = modelNextUserSingleUseCodeId m + 1 }
  m' `seq` put m'
  return i

-- | Set usage time of the single use code
setSingleUseCodeUsed :: UserSingleUseCodeId -> Maybe UTCTime -> Update Model ()
setSingleUseCodeUsed i mt = modify' $ \m -> m { modelUserSingleUseCodes = M.adjust (\v -> v { userSingleUseCodeUsed = mt }) i $ modelUserSingleUseCodes m }

-- | Find unused code for the user and expiration time greater than the given time
getUnusedCode :: SingleUseCode -> UserImplId -> UTCTime -> Query Model (Maybe (WithId UserSingleUseCodeId UserSingleUseCode))
getUnusedCode c i t = fmap (uncurry WithField) . headMay . sorting . M.toList . M.filter f <$> asks modelUserSingleUseCodes
  where
    sorting = sortBy (comparing $ Down . userSingleUseCodeExpire . snd)
    f UserSingleUseCode{..} =
         userSingleUseCodeValue == c
      && userSingleUseCodeUser == i
      && userSingleUseCodeUsed == Nothing
      && (userSingleUseCodeExpire == Nothing || userSingleUseCodeExpire >= Just t)

-- | Invalidate all permament codes for user and set use time for them
invalidatePermamentCodes :: UserImplId -> UTCTime -> Update Model ()
invalidatePermamentCodes i t = modify' $ \m -> m { modelUserSingleUseCodes = f $ modelUserSingleUseCodes m }
  where
    f m = (fmap invalidate . M.filter isPermament $ m) `M.union` m
    invalidate su = su { userSingleUseCodeUsed = Just t }
    isPermament UserSingleUseCode{..} =
         userSingleUseCodeUser == i
      && userSingleUseCodeUsed == Nothing
      && userSingleUseCodeExpire == Nothing

-- | Select last valid restoration code by the given current time
selectLastRestoreCode :: UserImplId -> UTCTime -> Query Model (Maybe (WithId UserRestoreId UserRestore))
selectLastRestoreCode i t = fmap (uncurry WithField) . headMay . sorting . M.toList . M.filter f <$> asks modelUserRestores
  where
    sorting = sortBy (comparing $ Down . userRestoreExpire . snd)
    f UserRestore{..} = userRestoreUser == i && userRestoreExpire > t

-- | Insert new restore code
insertUserRestore :: UserRestore -> Update Model UserRestoreId
insertUserRestore v = do
  m <- get
  let
    i = toKey $ modelNextUserRestoreId m
    vals = M.insert i v . modelUserRestores $ m
    m' = m { modelUserRestores = vals, modelNextUserRestoreId = modelNextUserRestoreId m + 1 }
  m' `seq` put m'
  return i

-- | Find unexpired by the time restore code
findRestoreCode :: UserImplId -> RestoreCode -> UTCTime -> Query Model (Maybe (WithId UserRestoreId UserRestore))
findRestoreCode i rc t = fmap (uncurry WithField) . headMay . sorting . M.toList . M.filter f <$> asks modelUserRestores
  where
    sorting = sortBy (comparing $ Down . userRestoreExpire . snd)
    f UserRestore{..} = userRestoreUser == i && userRestoreValue == rc && userRestoreExpire > t

-- | Replace restore code with new value
replaceRestoreCode :: UserRestoreId -> UserRestore -> Update Model ()
replaceRestoreCode i v = modify' $ \m -> m { modelUserRestores = M.insert i v $ modelUserRestores m }

-- | Find first non-expired by the time token for user
findAuthToken :: UserImplId -> UTCTime -> Query Model (Maybe (WithId AuthTokenId AuthToken))
findAuthToken i t = fmap (uncurry WithField) . headMay . M.toList . M.filter f <$> asks modelAuthTokens
  where
    f AuthToken{..} = authTokenUser == i && authTokenExpire > t

-- | Find token by value
findAuthTokenByValue :: SimpleToken -> Query Model (Maybe (WithId AuthTokenId AuthToken))
findAuthTokenByValue v = fmap (uncurry WithField) . headMay . M.toList . M.filter f <$> asks modelAuthTokens
  where
    f AuthToken{..} = authTokenValue == v

-- | Insert new token
insertAuthToken :: AuthToken -> Update Model AuthTokenId
insertAuthToken v = do
  m <- get
  let
    i = toKey $ modelNextAuthTokenId m
    vals = M.insert i v . modelAuthTokens $ m
    m' = m { modelAuthTokens = vals, modelNextAuthTokenId = modelNextAuthTokenId m + 1 }
  m' `seq` put m'
  return i

-- | Replace auth token with new value
replaceAuthToken :: AuthTokenId -> AuthToken -> Update Model ()
replaceAuthToken i v = modify' $ \m -> m { modelAuthTokens = M.insert i v $ modelAuthTokens m }

deriveSafeCopy 0 'base ''UserImplId
deriveSafeCopy 0 'base ''UserImpl
deriveSafeCopy 0 'base ''UserPermId
deriveSafeCopy 0 'base ''UserPerm
deriveSafeCopy 0 'base ''AuthTokenId
deriveSafeCopy 0 'base ''AuthToken
deriveSafeCopy 0 'base ''UserRestoreId
deriveSafeCopy 0 'base ''UserRestore
deriveSafeCopy 0 'base ''UserSingleUseCodeId
deriveSafeCopy 0 'base ''UserSingleUseCode
deriveSafeCopy 0 'base ''AuthUserGroupId
deriveSafeCopy 0 'base ''AuthUserGroup
deriveSafeCopy 0 'base ''AuthUserGroupUsersId
deriveSafeCopy 0 'base ''AuthUserGroupUsers
deriveSafeCopy 0 'base ''AuthUserGroupPermsId
deriveSafeCopy 0 'base ''AuthUserGroupPerms
deriveSafeCopy 0 'base ''Model

instance (SafeCopy k, SafeCopy v) => SafeCopy (WithField i k v) where
  putCopy (WithField k v) = contain $ do
    safePut k
    safePut v
  getCopy = contain $ WithField
    <$> safeGet
    <*> safeGet

makeAcidic ''Model [
    'getUserImpl
  , 'getUserImplByLogin
  , 'listUsersPaged
  , 'getUserImplPermissions
  , 'deleteUserPermissions
  , 'insertUserPerm
  , 'insertUserImpl
  , 'replaceUserImpl
  , 'deleteUserImpl
  , 'hasPerm
  , 'getFirstUserByPerm
  , 'selectUserImplGroups
  , 'clearUserImplGroups
  , 'insertAuthUserGroup
  , 'insertAuthUserGroupUsers
  , 'insertAuthUserGroupPerms
  , 'getAuthUserGroup
  , 'listAuthUserGroupPermissions
  , 'listAuthUserGroupUsers
  , 'replaceAuthUserGroup
  , 'clearAuthUserGroupUsers
  , 'clearAuthUserGroupPerms
  , 'deleteAuthUserGroup
  , 'listGroupsPaged
  , 'setAuthUserGroupName
  , 'setAuthUserGroupParent
  , 'insertSingleUseCode
  , 'setSingleUseCodeUsed
  , 'getUnusedCode
  , 'invalidatePermamentCodes
  , 'selectLastRestoreCode
  , 'insertUserRestore
  , 'findRestoreCode
  , 'replaceRestoreCode
  , 'findAuthToken
  , 'findAuthTokenByValue
  , 'insertAuthToken
  , 'replaceAuthToken
  ]
