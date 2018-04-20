{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE NoDisambiguateRecordFields, NoRecordWildCards #-}
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
import Language.Haskell.TH
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

-- | The end user should implement this for his global type
class HasModelRead a where
  askModel :: a -> Model

-- | The end user should implement this fot his global type
class HasModelRead a => HasModelWrite a where
  putModel :: a -> Model -> a

-- | List of queries of the backend. Can be used if you want additional queries alongside
-- with the auth ones.
--
-- Usage:
-- @
-- makeAcidic ''Model (acidQueries ++ [{- your queries herer-}])
-- @
acidQueries :: [Name]
acidQueries = [
    mkName "getUserImpl"
  , mkName "getUserImplByLogin"
  , mkName "listUsersPaged"
  , mkName "getUserImplPermissions"
  , mkName "deleteUserPermissions"
  , mkName "insertUserPerm"
  , mkName "insertUserImpl"
  , mkName "replaceUserImpl"
  , mkName "deleteUserImpl"
  , mkName "hasPerm"
  , mkName "getFirstUserByPerm"
  , mkName "selectUserImplGroups"
  , mkName "clearUserImplGroups"
  , mkName "insertAuthUserGroup"
  , mkName "insertAuthUserGroupUsers"
  , mkName "insertAuthUserGroupPerms"
  , mkName "getAuthUserGroup"
  , mkName "listAuthUserGroupPermissions"
  , mkName "listAuthUserGroupUsers"
  , mkName "replaceAuthUserGroup"
  , mkName "clearAuthUserGroupUsers"
  , mkName "clearAuthUserGroupPerms"
  , mkName "deleteAuthUserGroup"
  , mkName "listGroupsPaged"
  , mkName "setAuthUserGroupName"
  , mkName "setAuthUserGroupParent"
  , mkName "insertSingleUseCode"
  , mkName "setSingleUseCodeUsed"
  , mkName "getUnusedCode"
  , mkName "invalidatePermanentCodes"
  , mkName "selectLastRestoreCode"
  , mkName "insertUserRestore"
  , mkName "findRestoreCode"
  , mkName "replaceRestoreCode"
  , mkName "findAuthToken"
  , mkName "findAuthTokenByValue"
  , mkName "insertAuthToken"
  , mkName "replaceAuthToken"
  ]

-- | The end user should inline this TH in his code
makeModelAcidic :: Name -> DecsQ
makeModelAcidic globalStateName = makeAcidic globalStateName acidQueries

instance HasModelRead Model where
  askModel = id

instance HasModelWrite Model where
  putModel = const id

asksM :: HasModelRead a => (Model -> b) -> Query a b
asksM f = fmap (f . askModel) ask

modifyM :: HasModelWrite a => (Model -> Model) -> Update a ()
modifyM f = modify' (\a -> putModel a . f . askModel $ a)

getM :: HasModelWrite a => Update a Model
getM = fmap askModel get

putM :: HasModelWrite a => Model -> Update a ()
putM m = modifyM (const m)

-- | Mixin queries to work with auth state
deriveQueries :: Name -> DecsQ
deriveQueries globalStateName = [d|
    -- Getting user from storage
    getUserImpl :: HasModelRead $a => UserImplId -> Query $a (Maybe UserImpl)
    getUserImpl i = M.lookup i <$> asksM modelUsers

    -- Getting user from storage by login
    getUserImplByLogin :: HasModelRead $a => Login -> Query $a (Maybe (WithId UserImplId UserImpl))
    getUserImplByLogin l = M.lookup l <$> asksM modelUsersByLogin

    -- Helper to get page from map
    getPagedList :: Ord i => Page -> PageSize -> Map i a -> ([WithId i a], Word)
    getPagedList p s m = (uncurry WithField <$> es, fromIntegral $ F.length m)
      where
        es = take (fromIntegral s) . drop (fromIntegral $ p * s) . sortBy (comparing fst) . M.toList $ m

    -- Get paged list of users and total count of users
    listUsersPaged :: HasModelRead $a => Page -> PageSize -> Query $a ([WithId UserImplId UserImpl], Word)
    listUsersPaged p s = getPagedList p s <$> asksM modelUsers

    -- Get user permissions, ascending by tag
    getUserImplPermissions :: HasModelRead $a => UserImplId -> Query $a [WithId UserPermId UserPerm]
    getUserImplPermissions i = fmap (uncurry WithField) . M.toList . M.filter ((i ==) . userPermUser) <$> asksM modelUserPerms

    -- Delete user permissions
    deleteUserPermissions :: HasModelWrite $a => UserImplId -> Update $a ()
    deleteUserPermissions i = modifyM $ \m -> m { modelUserPerms = f $ modelUserPerms m }
      where
        f m = m `M.difference` M.filter ((i ==) . userPermUser) m

    -- Insertion of new user permission
    insertUserPerm :: HasModelWrite $a => UserPerm -> Update $a UserPermId
    insertUserPerm p = do
      m <- getM
      let
        i = toKey $ modelNextUserPermId m
        perms = M.insert i p . modelUserPerms $ m
        m' = m { modelUserPerms = perms, modelNextUserPermId = modelNextUserPermId m + 1 }
      m' `seq` putM m'
      return i

    -- Insertion of new user
    insertUserImpl :: HasModelWrite $a => UserImpl -> Update $a UserImplId
    insertUserImpl v = do
      m <- getM
      let
        i = toKey $ modelNextUserImplId m
        vals = M.insert i v . modelUsers $ m
        vals' = M.insert (userImplLogin v) (WithField i v) . modelUsersByLogin $ m
        m' = m { modelUsers = vals, modelUsersByLogin = vals', modelNextUserImplId = modelNextUserImplId m + 1 }
      m' `seq` putM m'
      return i

    -- Replace user with new value
    replaceUserImpl :: HasModelWrite $a => UserImplId -> UserImpl -> Update $a ()
    replaceUserImpl i v = modifyM $ \m -> m {
        modelUsers = M.insert i v . modelUsers $ m
      , modelUsersByLogin = M.insert (userImplLogin v) (WithField i v) . modelUsersByLogin $ m
      }

    -- Delete user by id
    deleteUserImpl :: HasModelWrite $a => UserImplId -> Update $a ()
    deleteUserImpl i = do
      deleteUserPermissions i
      modifyM $ \m -> case M.lookup i . modelUsers $ m of
        Nothing -> m
        Just ui -> m {
            modelUsers = M.delete i . modelUsers $ m
          , modelUsersByLogin = M.delete (userImplLogin ui) . modelUsersByLogin $ m
          }

    -- Check whether the user has particular permission
    hasPerm :: HasModelRead $a => UserImplId -> Permission -> Query $a Bool
    hasPerm i p = (> 0) . F.length . M.filter (\up -> userPermUser up == i && userPermPermission up == p) <$> asksM modelUserPerms

    -- Get any user with given permission
    getFirstUserByPerm :: HasModelRead $a => Permission -> Query $a (Maybe (WithId UserImplId UserImpl))
    getFirstUserByPerm perm = do
      m <- asksM modelUserPerms
      case M.toList . M.filter (\p -> userPermPermission p == perm) $ m of
        [] -> return Nothing
        ((_, p) : _) -> fmap (WithField $ userPermUser p) <$> getUserImpl (userPermUser p)

    -- Select user groups and sort them by ascending name
    selectUserImplGroups :: HasModelRead $a => UserImplId -> Query $a [WithId AuthUserGroupUsersId AuthUserGroupUsers]
    selectUserImplGroups i = fmap (uncurry WithField) . M.toList . M.filter ((i ==) . authUserGroupUsersUser) <$> asksM modelAuthUserGroupUsers

    -- Remove user from all groups
    clearUserImplGroups :: HasModelWrite $a => UserImplId -> Update $a ()
    clearUserImplGroups i = modifyM $ \m -> m { modelAuthUserGroupUsers = f $ modelAuthUserGroupUsers m }
      where
        f m = m `M.difference` M.filter ((i ==) . authUserGroupUsersUser) m

    -- Add new user group
    insertAuthUserGroup :: HasModelWrite $a => AuthUserGroup -> Update $a AuthUserGroupId
    insertAuthUserGroup v = do
      m <- getM
      let
        i = toKey $ modelNextAuthUserGroupId m
        vals = M.insert i v . modelAuthUserGroups $ m
        m' = m { modelAuthUserGroups = vals, modelNextAuthUserGroupId = modelNextAuthUserGroupId m + 1 }
      m' `seq` putM m'
      return i

    -- Add user to given group
    insertAuthUserGroupUsers :: HasModelWrite $a => AuthUserGroupUsers -> Update $a AuthUserGroupUsersId
    insertAuthUserGroupUsers v = do
      m <- getM
      let
        i = toKey $ modelNextAuthUserGroupUserId m
        vals = M.insert i v . modelAuthUserGroupUsers $ m
        m' = m { modelAuthUserGroupUsers = vals, modelNextAuthUserGroupUserId = modelNextAuthUserGroupUserId m + 1 }
      m' `seq` putM m'
      return i

    -- Add permission to given group
    insertAuthUserGroupPerms :: HasModelWrite $a => AuthUserGroupPerms -> Update $a AuthUserGroupPermsId
    insertAuthUserGroupPerms v = do
      m <- getM
      let
        i = toKey $ modelNextAuthUserGroupPermId m
        vals = M.insert i v . modelAuthUserGroupPerms $ m
        m' = m { modelAuthUserGroupPerms = vals, modelNextAuthUserGroupPermId = modelNextAuthUserGroupPermId m + 1 }
      m' `seq` putM m'
      return i

    -- Find user group by id
    getAuthUserGroup :: HasModelRead $a => AuthUserGroupId -> Query $a (Maybe AuthUserGroup)
    getAuthUserGroup i = M.lookup i <$> asksM modelAuthUserGroups

    -- Get list of permissions of given group
    listAuthUserGroupPermissions :: HasModelRead $a => AuthUserGroupId -> Query $a [WithId AuthUserGroupPermsId AuthUserGroupPerms]
    listAuthUserGroupPermissions i = fmap (uncurry WithField) . M.toList . M.filter ((i ==) . authUserGroupPermsGroup) <$> asksM modelAuthUserGroupPerms

    -- Get list of all users of the group
    listAuthUserGroupUsers :: HasModelRead $a => AuthUserGroupId -> Query $a [WithId AuthUserGroupUsersId AuthUserGroupUsers]
    listAuthUserGroupUsers i = fmap (uncurry WithField) . M.toList . M.filter ((i ==) . authUserGroupUsersGroup) <$> asksM modelAuthUserGroupUsers

    -- Replace record of user group
    replaceAuthUserGroup :: HasModelWrite $a => AuthUserGroupId -> AuthUserGroup -> Update $a ()
    replaceAuthUserGroup i v = modifyM $ \m -> m { modelAuthUserGroups = M.insert i v $ modelAuthUserGroups m }

    -- Remove all users from group
    clearAuthUserGroupUsers :: HasModelWrite $a => AuthUserGroupId -> Update $a ()
    clearAuthUserGroupUsers i = modifyM $ \m -> m { modelAuthUserGroupUsers = f $ modelAuthUserGroupUsers m }
      where
        f m = m `M.difference` M.filter ((i ==) . authUserGroupUsersGroup) m

    -- Remove all permissions from group
    clearAuthUserGroupPerms :: HasModelWrite $a => AuthUserGroupId -> Update $a ()
    clearAuthUserGroupPerms i = modifyM $ \m -> m { modelAuthUserGroupPerms = f $ modelAuthUserGroupPerms m }
      where
        f m = m `M.difference` M.filter ((i ==) . authUserGroupPermsGroup) m

    -- Delete user group from storage
    deleteAuthUserGroup :: HasModelWrite $a => AuthUserGroupId -> Update $a ()
    deleteAuthUserGroup i = do
      clearAuthUserGroupUsers i
      clearAuthUserGroupPerms i
      modifyM $ \m -> m { modelAuthUserGroups = M.delete i $ modelAuthUserGroups m }

    -- Get paged list of user groups with total count
    listGroupsPaged :: HasModelRead $a => Page -> PageSize -> Query $a ([WithId AuthUserGroupId AuthUserGroup], Word)
    listGroupsPaged p s = getPagedList p s <$> asksM modelAuthUserGroups

    -- Set group name
    setAuthUserGroupName :: HasModelWrite $a => AuthUserGroupId -> Text -> Update $a ()
    setAuthUserGroupName i n = modifyM $ \m -> m { modelAuthUserGroups = M.adjust (\v -> v { authUserGroupName = n }) i $ modelAuthUserGroups m }

    -- Set group parent
    setAuthUserGroupParent :: HasModelWrite $a => AuthUserGroupId -> Maybe AuthUserGroupId -> Update $a ()
    setAuthUserGroupParent i p = modifyM $ \m -> m { modelAuthUserGroups = M.adjust (\v -> v { authUserGroupParent = p }) i $ modelAuthUserGroups m }

    -- Add new single use code
    insertSingleUseCode :: HasModelWrite $a => UserSingleUseCode -> Update $a UserSingleUseCodeId
    insertSingleUseCode v = do
      m <- getM
      let
        i = toKey $ modelNextUserSingleUseCodeId m
        vals = M.insert i v . modelUserSingleUseCodes $ m
        m' = m { modelUserSingleUseCodes = vals, modelNextUserSingleUseCodeId = modelNextUserSingleUseCodeId m + 1 }
      m' `seq` putM m'
      return i

    -- Set usage time of the single use code
    setSingleUseCodeUsed :: HasModelWrite $a => UserSingleUseCodeId -> Maybe UTCTime -> Update $a ()
    setSingleUseCodeUsed i mt = modifyM $ \m -> m { modelUserSingleUseCodes = M.adjust (\v -> v { userSingleUseCodeUsed = mt }) i $ modelUserSingleUseCodes m }

    -- Find unused code for the user and expiration time greater than the given time
    getUnusedCode :: HasModelRead $a => SingleUseCode -> UserImplId -> UTCTime -> Query $a (Maybe (WithId UserSingleUseCodeId UserSingleUseCode))
    getUnusedCode c i t = fmap (uncurry WithField) . headMay . sorting . M.toList . M.filter f <$> asksM modelUserSingleUseCodes
      where
        sorting = sortBy (comparing $ Down . userSingleUseCodeExpire . snd)
        f usc =
             userSingleUseCodeValue usc == c
          && userSingleUseCodeUser usc == i
          && userSingleUseCodeUsed usc == Nothing
          && (userSingleUseCodeExpire usc == Nothing || userSingleUseCodeExpire usc >= Just t)

    -- Invalidate all permanent codes for user and set use time for them
    invalidatePermanentCodes :: HasModelWrite $a => UserImplId -> UTCTime -> Update $a ()
    invalidatePermanentCodes i t = modifyM $ \m -> m { modelUserSingleUseCodes = f $ modelUserSingleUseCodes m }
      where
        f m = (fmap invalidate . M.filter isPermanent $ m) `M.union` m
        invalidate su = su { userSingleUseCodeUsed = Just t }
        isPermanent usc =
             userSingleUseCodeUser usc == i
          && userSingleUseCodeUsed usc == Nothing
          && userSingleUseCodeExpire usc == Nothing

    -- Select last valid restoration code by the given current time
    selectLastRestoreCode :: HasModelRead $a => UserImplId -> UTCTime -> Query $a (Maybe (WithId UserRestoreId UserRestore))
    selectLastRestoreCode i t = fmap (uncurry WithField) . headMay . sorting . M.toList . M.filter f <$> asksM modelUserRestores
      where
        sorting = sortBy (comparing $ Down . userRestoreExpire . snd)
        f ur = userRestoreUser ur == i && userRestoreExpire ur > t

    -- Insert new restore code
    insertUserRestore :: HasModelWrite $a => UserRestore -> Update $a UserRestoreId
    insertUserRestore v = do
      m <- getM
      let
        i = toKey $ modelNextUserRestoreId m
        vals = M.insert i v . modelUserRestores $ m
        m' = m { modelUserRestores = vals, modelNextUserRestoreId = modelNextUserRestoreId m + 1 }
      m' `seq` putM m'
      return i

    -- Find unexpired by the time restore code
    findRestoreCode :: HasModelRead $a => UserImplId -> RestoreCode -> UTCTime -> Query $a (Maybe (WithId UserRestoreId UserRestore))
    findRestoreCode i rc t = fmap (uncurry WithField) . headMay . sorting . M.toList . M.filter f <$> asksM modelUserRestores
      where
        sorting = sortBy (comparing $ Down . userRestoreExpire . snd)
        f ur = userRestoreUser ur == i && userRestoreValue ur == rc && userRestoreExpire ur > t

    -- Replace restore code with new value
    replaceRestoreCode :: HasModelWrite $a => UserRestoreId -> UserRestore -> Update $a ()
    replaceRestoreCode i v = modifyM $ \m -> m { modelUserRestores = M.insert i v $ modelUserRestores m }

    -- Find first non-expired by the time token for user
    findAuthToken :: HasModelRead $a => UserImplId -> UTCTime -> Query $a (Maybe (WithId AuthTokenId AuthToken))
    findAuthToken i t = fmap (uncurry WithField) . headMay . M.toList . M.filter f <$> asksM modelAuthTokens
      where
        f atok = authTokenUser atok == i && authTokenExpire atok > t

    -- Find token by value
    findAuthTokenByValue :: HasModelRead $a => SimpleToken -> Query $a (Maybe (WithId AuthTokenId AuthToken))
    findAuthTokenByValue v = fmap (uncurry WithField) . headMay . M.toList . M.filter f <$> asksM modelAuthTokens
      where
        f atok = authTokenValue atok == v

    -- Insert new token
    insertAuthToken :: HasModelWrite $a => AuthToken -> Update $a AuthTokenId
    insertAuthToken v = do
      m <- getM
      let
        i = toKey $ modelNextAuthTokenId m
        vals = M.insert i v . modelAuthTokens $ m
        m' = m { modelAuthTokens = vals, modelNextAuthTokenId = modelNextAuthTokenId m + 1 }
      m' `seq` putM m'
      return i

    -- Replace auth token with new value
    replaceAuthToken :: HasModelWrite $a => AuthTokenId -> AuthToken -> Update $a ()
    replaceAuthToken i v = modifyM $ \m -> m { modelAuthTokens = M.insert i v $ modelAuthTokens m }
    |]
  where
    a = conT globalStateName

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
