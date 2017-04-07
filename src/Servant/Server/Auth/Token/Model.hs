{-|
Module      : Servant.Server.Auth.Token.Model
Description : Internal operations with RDBMS
Copyright   : (c) Anton Gushcha, 2016
License     : MIT
Maintainer  : ncrashed@gmail.com
Stability   : experimental
Portability : Portable
-}
module Servant.Server.Auth.Token.Model(
  -- * DB entities
    UserImpl(..)
  , UserPerm(..)
  , AuthToken(..)
  , UserRestore(..)
  , AuthUserGroup(..)
  , AuthUserGroupUsers(..)
  , AuthUserGroupPerms(..)
  , UserSingleUseCode(..)
  -- * IDs of entities
  , UserImplId
  , UserPermId
  , AuthTokenId
  , UserRestoreId
  , AuthUserGroupId
  , AuthUserGroupUsersId
  , AuthUserGroupPermsId
  , UserSingleUseCodeId
  -- * DB interface
  , HasStorage(..)
  -- * Operations
  , passToByteString
  , byteStringToPass
  -- ** User
  , userToUserInfo
  , readUserInfo
  , readUserInfoByLogin
  , getUserPermissions
  , setUserPermissions
  , createUser
  , hasPerms
  , createAdmin
  , ensureAdmin
  , patchUser
  , setUserPassword'
  -- ** User groups
  , getUserGroups
  , setUserGroups
  , validateGroups
  , getGroupPermissions
  , getUserGroupPermissions
  , getUserAllPermissions
  , readUserGroup
  , toAuthUserGroup
  , insertUserGroup
  , updateUserGroup
  , deleteUserGroup
  , patchUserGroup
  -- * Low-level
  , makeUserInfo
  ) where

import Control.Monad
import Control.Monad.IO.Class
import Crypto.PasswordStore
import Data.Aeson.WithField
import Data.Int
import Data.Maybe
import Data.Monoid
import Data.Text (Text)
import Data.Time
import GHC.Generics

import qualified Data.ByteString as BS
import qualified Data.Foldable as F
import qualified Data.List as L
import qualified Data.Sequence as S
import qualified Data.Text.Encoding as TE

import Servant.API.Auth.Token
import Servant.API.Auth.Token.Pagination
import Servant.Server.Auth.Token.Common
import Servant.Server.Auth.Token.Patch

-- | ID of user
newtype UserImplId = UserImplId { unUserImplId :: Int64 }
  deriving (Generic, Show, Eq, Ord)

instance ConvertableKey UserImplId where
  toKey = UserImplId . fromIntegral
  fromKey = fromIntegral . unUserImplId
  {-# INLINE toKey #-}
  {-# INLINE fromKey #-}

-- | Internal user implementation
data UserImpl = UserImpl {
  userImplLogin    :: !Login -- ^ Unique user login
, userImplPassword :: !Password -- ^ Password encrypted with salt
, userImplEmail    :: !Email -- ^ User email
} deriving (Generic, Show)

-- | ID of user permission
newtype UserPermId = UserPermId { unUserPermId :: Int64 }
  deriving (Generic, Show, Eq, Ord)

instance ConvertableKey UserPermId where
  toKey = UserPermId . fromIntegral
  fromKey = fromIntegral . unUserPermId
  {-# INLINE toKey #-}
  {-# INLINE fromKey #-}

-- | Internal implementation of permission (1-M)
data UserPerm = UserPerm {
  userPermUser       :: !UserImplId -- ^ Reference to user
, userPermPermission :: !Permission -- ^ Permission tag
} deriving (Generic, Show)

-- | ID of authorisation token
newtype AuthTokenId = AuthTokenId { unAuthTokenId :: Int64 }
  deriving (Generic, Show, Eq, Ord)

instance ConvertableKey AuthTokenId where
  toKey = AuthTokenId . fromIntegral
  fromKey = fromIntegral . unAuthTokenId
  {-# INLINE toKey #-}
  {-# INLINE fromKey #-}

-- | Internal implementation of authorisation token
data AuthToken = AuthToken {
  authTokenValue  :: !SimpleToken -- ^ Value of token
, authTokenUser   :: !UserImplId -- ^ Reference to user of the token
, authTokenExpire :: !UTCTime -- ^ When the token expires
} deriving (Generic, Show)

-- | ID of restoration code
newtype UserRestoreId = UserRestoreId { unUserRestoreId :: Int64 }
  deriving (Generic, Show, Eq, Ord)

instance ConvertableKey UserRestoreId where
  toKey = UserRestoreId . fromIntegral
  fromKey = fromIntegral . unUserRestoreId
  {-# INLINE toKey #-}
  {-# INLINE fromKey #-}

-- | Internal implementation of restoration code
data UserRestore = UserRestore {
  userRestoreValue  :: !RestoreCode -- ^ Code value
, userRestoreUser   :: !UserImplId -- ^ Reference to user that the code restores
, userRestoreExpire :: !UTCTime -- ^ When the code expires
} deriving (Generic, Show)

-- | ID of single use code
newtype UserSingleUseCodeId = UserSingleUseCodeId { unUserSingleUseCodeId :: Int64 }
  deriving (Generic, Show, Eq, Ord)

instance ConvertableKey UserSingleUseCodeId where
  toKey = UserSingleUseCodeId . fromIntegral
  fromKey = fromIntegral . unUserSingleUseCodeId
  {-# INLINE toKey #-}
  {-# INLINE fromKey #-}

-- | Internal implementation of single use code
data UserSingleUseCode = UserSingleUseCode {
  userSingleUseCodeValue  :: !SingleUseCode -- ^ Value of single use code
, userSingleUseCodeUser   :: !UserImplId -- ^ Reference to user the code is owned by
, userSingleUseCodeExpire :: !(Maybe UTCTime) -- ^ When the code expires, 'Nothing' is code that never expires
, userSingleUseCodeUsed   :: !(Maybe UTCTime) -- ^ When the code was used
} deriving (Generic, Show)

-- | ID of user group
newtype AuthUserGroupId = AuthUserGroupId { unAuthUserGroupId :: Int64 }
  deriving (Generic, Show, Eq, Ord)

instance ConvertableKey AuthUserGroupId where
  toKey = AuthUserGroupId . fromIntegral
  fromKey = fromIntegral . unAuthUserGroupId
  {-# INLINE toKey #-}
  {-# INLINE fromKey #-}

-- | Internal implementation of user group
data AuthUserGroup = AuthUserGroup {
  authUserGroupName   :: !Text -- ^ Name of group
, authUserGroupParent :: !(Maybe AuthUserGroupId) -- ^ Can be a child of another group
} deriving (Generic, Show)

-- | ID of user-group binding
newtype AuthUserGroupUsersId = AuthUserGroupUsersId { unAuthUserGroupUsersId :: Int64 }
  deriving (Generic, Show, Eq, Ord)

instance ConvertableKey AuthUserGroupUsersId where
  toKey = AuthUserGroupUsersId . fromIntegral
  fromKey = fromIntegral . unAuthUserGroupUsersId
  {-# INLINE toKey #-}
  {-# INLINE fromKey #-}

-- | Implementation of M-M between user and group
data AuthUserGroupUsers = AuthUserGroupUsers {
  authUserGroupUsersGroup :: !AuthUserGroupId
, authUserGroupUsersUser  :: !UserImplId
} deriving (Generic, Show)

-- | ID of permission-group binding
newtype AuthUserGroupPermsId = AuthUserGroupPermsId { unAuthUserGroupPermsId :: Int64 }
  deriving (Generic, Show, Eq, Ord)

instance ConvertableKey AuthUserGroupPermsId where
  toKey = AuthUserGroupPermsId . fromIntegral
  fromKey = fromIntegral . unAuthUserGroupPermsId
  {-# INLINE toKey #-}
  {-# INLINE fromKey #-}

-- | Implementation of M-M between permission and group
data AuthUserGroupPerms = AuthUserGroupPerms {
  authUserGroupPermsGroup      :: AuthUserGroupId
, authUserGroupPermsPermission :: Permission
} deriving (Generic, Show)

-- | Abstract storage interface. External libraries can implement this in terms
-- of PostgreSQL or acid-state.
class MonadIO m => HasStorage m where
  -- | Getting user from storage
  getUserImpl :: UserImplId -> m (Maybe UserImpl)
  -- | Getting user from storage by login
  getUserImplByLogin :: Login -> m (Maybe (WithId UserImplId UserImpl))
  -- | Get paged list of users and total count of users
  listUsersPaged :: Page -> PageSize -> m ([WithId UserImplId UserImpl], Word)
  -- | Get user permissions, ascending by tag
  getUserImplPermissions :: UserImplId -> m [WithId UserPermId UserPerm]
  -- | Delete user permissions
  deleteUserPermissions :: UserImplId -> m ()
  -- | Insertion of new user permission
  insertUserPerm :: UserPerm -> m UserPermId
  -- | Insertion of new user
  insertUserImpl :: UserImpl -> m UserImplId
  -- | Replace user with new value
  replaceUserImpl :: UserImplId -> UserImpl -> m ()
  -- | Delete user by id
  deleteUserImpl :: UserImplId -> m ()
  -- | Check whether the user has particular permission
  hasPerm :: UserImplId -> Permission -> m Bool
  -- | Get any user with given permission
  getFirstUserByPerm :: Permission -> m (Maybe (WithId UserImplId UserImpl))
  -- | Select user groups and sort them by ascending name
  selectUserImplGroups :: UserImplId -> m [WithId AuthUserGroupUsersId AuthUserGroupUsers]
  -- | Remove user from all groups
  clearUserImplGroups :: UserImplId -> m ()
  -- | Add new user group
  insertAuthUserGroup :: AuthUserGroup -> m AuthUserGroupId
  -- | Add user to given group
  insertAuthUserGroupUsers :: AuthUserGroupUsers -> m AuthUserGroupUsersId
  -- | Add permission to given group
  insertAuthUserGroupPerms :: AuthUserGroupPerms -> m AuthUserGroupPermsId
  -- | Find user group by id
  getAuthUserGroup :: AuthUserGroupId -> m (Maybe AuthUserGroup)
  -- | Get list of permissions of given group
  listAuthUserGroupPermissions :: AuthUserGroupId -> m [WithId AuthUserGroupPermsId AuthUserGroupPerms]
  -- | Get list of all users of the group
  listAuthUserGroupUsers :: AuthUserGroupId -> m [WithId AuthUserGroupUsersId AuthUserGroupUsers]
  -- | Replace record of user group
  replaceAuthUserGroup :: AuthUserGroupId -> AuthUserGroup -> m ()
  -- | Remove all users from group
  clearAuthUserGroupUsers :: AuthUserGroupId -> m ()
  -- | Remove all permissions from group
  clearAuthUserGroupPerms :: AuthUserGroupId -> m ()
  -- | Delete user group from storage
  deleteAuthUserGroup :: AuthUserGroupId -> m ()
  -- | Get paged list of user groups with total count
  listGroupsPaged :: Page -> PageSize -> m ([WithId AuthUserGroupId AuthUserGroup], Word)
  -- | Set group name
  setAuthUserGroupName :: AuthUserGroupId -> Text -> m ()
  -- | Set group parent
  setAuthUserGroupParent :: AuthUserGroupId -> Maybe AuthUserGroupId -> m ()
  -- | Add new single use code
  insertSingleUseCode :: UserSingleUseCode -> m UserSingleUseCodeId
  -- | Set usage time of the single use code
  setSingleUseCodeUsed :: UserSingleUseCodeId -> Maybe UTCTime -> m ()
  -- | Find unused code for the user and expiration time greater than the given time
  getUnusedCode :: SingleUseCode -> UserImplId -> UTCTime -> m (Maybe (WithId UserSingleUseCodeId UserSingleUseCode))
  -- | Invalidate all permament codes for user and set use time for them
  invalidatePermamentCodes :: UserImplId -> UTCTime -> m ()
  -- | Select last valid restoration code by the given current time
  selectLastRestoreCode :: UserImplId -> UTCTime -> m (Maybe (WithId UserRestoreId UserRestore))
  -- | Insert new restore code
  insertUserRestore :: UserRestore -> m UserRestoreId
  -- | Find unexpired by the time restore code
  findRestoreCode :: UserImplId -> RestoreCode -> UTCTime -> m (Maybe (WithId UserRestoreId UserRestore))
  -- | Replace restore code with new value
  replaceRestoreCode :: UserRestoreId -> UserRestore -> m ()
  -- | Find first non-expired by the time token for user
  findAuthToken :: UserImplId -> UTCTime -> m (Maybe (WithId AuthTokenId AuthToken))
  -- | Find token by value
  findAuthTokenByValue :: SimpleToken -> m (Maybe (WithId AuthTokenId AuthToken))
  -- | Insert new token
  insertAuthToken :: AuthToken -> m AuthTokenId
  -- | Replace auth token with new value
  replaceAuthToken :: AuthTokenId -> AuthToken -> m ()

-- | Convert password to bytestring
passToByteString :: Password -> BS.ByteString
passToByteString = TE.encodeUtf8

-- | Convert bytestring into password
byteStringToPass :: BS.ByteString -> Password
byteStringToPass = TE.decodeUtf8

-- | Helper to convert user to response
userToUserInfo :: WithId UserImplId UserImpl -> [Permission] -> [UserGroupId] -> RespUserInfo
userToUserInfo (WithField uid UserImpl{..}) perms groups = RespUserInfo {
      respUserId = fromKey uid
    , respUserLogin = userImplLogin
    , respUserEmail = userImplEmail
    , respUserPermissions = perms
    , respUserGroups = groups
  }

-- | Low level operation for collecting info about user
makeUserInfo :: HasStorage m => WithId UserImplId UserImpl -> m RespUserInfo
makeUserInfo euser@(WithField uid _) = do
  perms <- getUserPermissions uid
  groups <- getUserGroups uid
  return $ userToUserInfo euser perms groups

-- | Get user by id
readUserInfo :: HasStorage m => UserId -> m (Maybe RespUserInfo)
readUserInfo uid' = do
  let uid = toKey uid'
  muser <- getUserImpl uid
  maybe (return Nothing) (fmap Just . makeUserInfo . WithField uid) $ muser

-- | Get user by login
readUserInfoByLogin :: HasStorage m => Login -> m (Maybe RespUserInfo)
readUserInfoByLogin login = do
  muser <- getUserImplByLogin login
  maybe (return Nothing) (fmap Just . makeUserInfo) muser

-- | Return list of permissions for the given user (only permissions that are assigned to him directly)
getUserPermissions :: HasStorage m => UserImplId -> m [Permission]
getUserPermissions uid = do
  perms <- getUserImplPermissions uid
  return $ userPermPermission . (\(WithField _ v) -> v) <$> perms

-- | Return list of permissions for the given user
setUserPermissions :: HasStorage m => UserImplId -> [Permission] -> m ()
setUserPermissions uid perms = do
  deleteUserPermissions uid
  forM_ perms $ void . insertUserPerm . UserPerm uid

-- | Creation of new user
createUser :: HasStorage m => Int -> Login -> Password -> Email -> [Permission] -> m UserImplId
createUser strength login pass email perms = do
  pass' <- liftIO $ makePassword (passToByteString pass) strength
  i <- insertUserImpl UserImpl {
      userImplLogin = login
    , userImplPassword = byteStringToPass pass'
    , userImplEmail = email
    }
  forM_ perms $ void . insertUserPerm . UserPerm i
  return i

-- | Check whether the user has particular permissions
hasPerms :: HasStorage m => UserImplId -> [Permission] -> m Bool
hasPerms _ [] = return True
hasPerms i perms = do
  perms' <- getUserAllPermissions i
  return $ and $ (`elem` perms') <$> perms

-- | Creates user with admin privileges
createAdmin :: HasStorage m => Int -> Login -> Password -> Email -> m UserImplId
createAdmin strength login pass email = createUser strength login pass email [adminPerm]

-- | Ensures that DB has at leas one admin, if not, creates a new one
-- with specified info.
ensureAdmin :: HasStorage m => Int -> Login -> Password -> Email -> m ()
ensureAdmin strength login pass email = do
  madmin <- getFirstUserByPerm adminPerm
  whenNothing madmin $ void $ createAdmin strength login pass email

-- | Apply patches for user
patchUser :: HasStorage m => Int -- ^ Password strength
  -> PatchUser -> WithId UserImplId UserImpl -> m (WithId UserImplId UserImpl)
patchUser strength PatchUser{..} =
        withPatch patchUserLogin (\l (WithField i u) -> pure $ WithField i u { userImplLogin = l })
    >=> withPatch patchUserPassword patchPassword
    >=> withPatch patchUserEmail (\e (WithField i u) -> pure $ WithField i u { userImplEmail = e })
    >=> withPatch patchUserPermissions patchPerms
    >=> withPatch patchUserGroups patchGroups
    where
      patchPassword ps (WithField i u) = WithField <$> pure i <*> setUserPassword' strength ps u
      patchPerms ps (WithField i u) = do
        setUserPermissions i ps
        return $ WithField i u
      patchGroups gs (WithField i u) = do
        setUserGroups i gs
        return $ WithField i u

-- | Update password of user
setUserPassword' :: MonadIO m => Int -- ^ Password strength
  -> Password -> UserImpl -> m UserImpl
setUserPassword' strength pass user = do
  pass' <- liftIO $ makePassword (passToByteString pass) strength
  return $ user { userImplPassword = byteStringToPass pass' }

-- | Get all groups the user belongs to
getUserGroups :: HasStorage m => UserImplId -> m [UserGroupId]
getUserGroups i = fmap (fromKey . authUserGroupUsersGroup . (\(WithField _ v) -> v)) <$> selectUserImplGroups i

-- | Rewrite all user groups
setUserGroups :: HasStorage m => UserImplId -> [UserGroupId] -> m ()
setUserGroups i gs = do
  clearUserImplGroups i
  gs' <- validateGroups gs
  forM_ gs' $ \g -> void $ insertAuthUserGroupUsers $ AuthUserGroupUsers g i

-- | Leave only existing groups
validateGroups :: HasStorage m => [UserGroupId] -> m [AuthUserGroupId]
validateGroups is = do
  pairs <- mapM ((\i -> (i,) <$> getAuthUserGroup i) . toKey) is
  return $ fmap fst . filter (isJust . snd) $ pairs

-- | Getting permission of a group and all it parent groups
getGroupPermissions :: HasStorage m => UserGroupId -> m [Permission]
getGroupPermissions = go S.empty S.empty . toKey
  where
  go !visited !perms !i = do
    mg <- getAuthUserGroup i
    case mg of
      Nothing -> return $ F.toList perms
      Just AuthUserGroup{..} -> do
        curPerms <- fmap (authUserGroupPermsPermission . (\(WithField _ v) -> v)) <$> listAuthUserGroupPermissions i
        let perms' = perms <> S.fromList curPerms
        case authUserGroupParent of
          Nothing -> return $ F.toList perms'
          Just pid -> if isJust $ pid `S.elemIndexL` visited
            then fail $ "Recursive user group graph: " <> show (visited S.|> pid)
            else go (visited S.|> pid) perms' pid

-- | Get user permissions that are assigned to him/her via groups only
getUserGroupPermissions :: HasStorage m => UserImplId -> m [Permission]
getUserGroupPermissions i = do
  groups <- getUserGroups i
  perms <- mapM getGroupPermissions groups
  return $ L.sort . L.nub . concat $ perms

-- | Get user permissions that are assigned to him/her either by direct
-- way or by his/her groups.
getUserAllPermissions :: HasStorage m => UserImplId -> m [Permission]
getUserAllPermissions i = do
  permsDr <- getUserPermissions i
  permsGr <- getUserGroupPermissions i
  return $ L.sort . L.nub $ permsDr <> permsGr

-- | Collect full info about user group from RDBMS
readUserGroup :: HasStorage m => UserGroupId -> m (Maybe UserGroup)
readUserGroup i = do
  let i' = toKey $ i
  mu <- getAuthUserGroup i'
  case mu of
    Nothing -> return Nothing
    Just AuthUserGroup{..} -> do
      users <- fmap (authUserGroupUsersUser . (\(WithField _ v) -> v)) <$> listAuthUserGroupUsers i'
      perms <- fmap (authUserGroupPermsPermission . (\(WithField _ v) -> v)) <$> listAuthUserGroupPermissions i'
      return $ Just UserGroup {
          userGroupName = authUserGroupName
        , userGroupUsers = fromKey <$> users
        , userGroupPermissions = perms
        , userGroupParent = fromKey <$> authUserGroupParent
        }

-- | Helper to convert user group into values of several tables
toAuthUserGroup :: UserGroup -> (AuthUserGroup, AuthUserGroupId -> [AuthUserGroupUsers], AuthUserGroupId -> [AuthUserGroupPerms])
toAuthUserGroup UserGroup{..} = (ag, users, perms)
  where
  ag = AuthUserGroup {
      authUserGroupName = userGroupName
    , authUserGroupParent = toKey <$> userGroupParent
    }
  users i = (\ui   -> AuthUserGroupUsers i (toKey $ ui)) <$> userGroupUsers
  perms i = (\perm -> AuthUserGroupPerms i perm) <$> userGroupPermissions

-- | Insert user group into RDBMS
insertUserGroup :: HasStorage m => UserGroup -> m UserGroupId
insertUserGroup u = do
  let (ag, users, perms) = toAuthUserGroup u
  i <- insertAuthUserGroup ag
  forM_ (users i) $ void . insertAuthUserGroupUsers
  forM_ (perms i) $ void . insertAuthUserGroupPerms
  return $ fromKey $ i

-- | Replace user group with new value
updateUserGroup :: HasStorage m => UserGroupId -> UserGroup -> m ()
updateUserGroup i u = do
  let i' = toKey $ i
  let (ag, users, perms) = toAuthUserGroup u
  replaceAuthUserGroup i' ag
  clearAuthUserGroupUsers i'
  clearAuthUserGroupPerms i'
  forM_ (users i') $ void . insertAuthUserGroupUsers
  forM_ (perms i') $ void . insertAuthUserGroupPerms

-- | Erase user group from RDBMS, cascade
deleteUserGroup :: HasStorage m => UserGroupId -> m ()
deleteUserGroup i = do
  let i' = toKey $ i
  clearAuthUserGroupUsers i'
  clearAuthUserGroupPerms i'
  deleteAuthUserGroup i'

-- | Partial update of user group
patchUserGroup :: HasStorage m => UserGroupId -> PatchUserGroup -> m ()
patchUserGroup i PatchUserGroup{..} = do
  let i' = toKey i
  whenJust patchUserGroupName $ setAuthUserGroupName i'
  whenJust patchUserGroupParent $ setAuthUserGroupParent i' . Just . toKey
  whenJust patchUserGroupNoParent $ const $ setAuthUserGroupParent i' Nothing
  whenJust patchUserGroupUsers $ \uids -> do
    clearAuthUserGroupUsers i'
    forM_ uids $ insertAuthUserGroupUsers . AuthUserGroupUsers i' . toKey
  whenJust patchUserGroupPermissions $ \perms -> do
    clearAuthUserGroupPerms i'
    forM_ perms $ insertAuthUserGroupPerms . AuthUserGroupPerms i'
