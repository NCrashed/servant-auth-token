{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE MultiWayIf #-}
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
  , readPwHash
  ) where

import Control.Monad
import Control.Monad.Cont (ContT)
import Control.Monad.Except (ExceptT)
import Control.Monad.IO.Class
import Control.Monad.Reader (ReaderT)
import Control.Monad.Trans.Class (MonadTrans(lift))
import Crypto.PasswordStore
import Data.Aeson.WithField
import Data.ByteString (ByteString)
import Data.Int
import Data.Maybe
import Data.Monoid
import Data.Text (Text)
import Data.Time
import GHC.Generics

import qualified Control.Monad.RWS.Lazy as LRWS
import qualified Control.Monad.RWS.Strict as SRWS
import qualified Control.Monad.State.Lazy as LS
import qualified Control.Monad.State.Strict as SS
import qualified Control.Monad.Writer.Lazy as LW
import qualified Control.Monad.Writer.Strict as SW
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
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
  default getUserImpl :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> m (Maybe UserImpl)
  getUserImpl = lift . getUserImpl

  -- | Getting user from storage by login
  getUserImplByLogin :: Login -> m (Maybe (WithId UserImplId UserImpl))
  default getUserImplByLogin :: (m ~ t n, MonadTrans t, HasStorage n) => Login -> m (Maybe (WithId UserImplId UserImpl))
  getUserImplByLogin = lift . getUserImplByLogin

  -- | Get paged list of users and total count of users
  listUsersPaged :: Page -> PageSize -> m ([WithId UserImplId UserImpl], Word)
  default listUsersPaged :: (m ~ t n, MonadTrans t, HasStorage n) => Page -> PageSize -> m ([WithId UserImplId UserImpl], Word)
  listUsersPaged = (lift .) . listUsersPaged

  -- | Get user permissions, ascending by tag
  getUserImplPermissions :: UserImplId -> m [WithId UserPermId UserPerm]
  default getUserImplPermissions :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> m [WithId UserPermId UserPerm]
  getUserImplPermissions = lift . getUserImplPermissions

  -- | Delete user permissions
  deleteUserPermissions :: UserImplId -> m ()
  default deleteUserPermissions :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> m ()
  deleteUserPermissions = lift . deleteUserPermissions

  -- | Insertion of new user permission
  insertUserPerm :: UserPerm -> m UserPermId
  default insertUserPerm :: (m ~ t n, MonadTrans t, HasStorage n) => UserPerm -> m UserPermId
  insertUserPerm = lift . insertUserPerm

  -- | Insertion of new user
  insertUserImpl :: UserImpl -> m UserImplId
  default insertUserImpl :: (m ~ t n, MonadTrans t, HasStorage n) => UserImpl -> m UserImplId
  insertUserImpl = lift . insertUserImpl

  -- | Replace user with new value
  replaceUserImpl :: UserImplId -> UserImpl -> m ()
  default replaceUserImpl :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> UserImpl -> m ()
  replaceUserImpl = (lift .) . replaceUserImpl

  -- | Delete user by id
  deleteUserImpl :: UserImplId -> m ()
  default deleteUserImpl :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> m ()
  deleteUserImpl = lift . deleteUserImpl

  -- | Check whether the user has particular permission
  hasPerm :: UserImplId -> Permission -> m Bool
  default hasPerm :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> Permission -> m Bool
  hasPerm = (lift .) . hasPerm

  -- | Get any user with given permission
  getFirstUserByPerm :: Permission -> m (Maybe (WithId UserImplId UserImpl))
  default getFirstUserByPerm :: (m ~ t n, MonadTrans t, HasStorage n) => Permission -> m (Maybe (WithId UserImplId UserImpl))
  getFirstUserByPerm = lift . getFirstUserByPerm

  -- | Select user groups and sort them by ascending name
  selectUserImplGroups :: UserImplId -> m [WithId AuthUserGroupUsersId AuthUserGroupUsers]
  default selectUserImplGroups :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> m [WithId AuthUserGroupUsersId AuthUserGroupUsers]
  selectUserImplGroups = lift . selectUserImplGroups

  -- | Remove user from all groups
  clearUserImplGroups :: UserImplId -> m ()
  default clearUserImplGroups :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> m ()
  clearUserImplGroups = lift . clearUserImplGroups

  -- | Add new user group
  insertAuthUserGroup :: AuthUserGroup -> m AuthUserGroupId
  default insertAuthUserGroup :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroup -> m AuthUserGroupId
  insertAuthUserGroup = lift . insertAuthUserGroup

  -- | Add user to given group
  insertAuthUserGroupUsers :: AuthUserGroupUsers -> m AuthUserGroupUsersId
  default insertAuthUserGroupUsers :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroupUsers -> m AuthUserGroupUsersId
  insertAuthUserGroupUsers = lift . insertAuthUserGroupUsers

  -- | Add permission to given group
  insertAuthUserGroupPerms :: AuthUserGroupPerms -> m AuthUserGroupPermsId
  default insertAuthUserGroupPerms :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroupPerms -> m AuthUserGroupPermsId
  insertAuthUserGroupPerms = lift . insertAuthUserGroupPerms

  -- | Find user group by id
  getAuthUserGroup :: AuthUserGroupId -> m (Maybe AuthUserGroup)
  default getAuthUserGroup :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroupId -> m (Maybe AuthUserGroup)
  getAuthUserGroup = lift . getAuthUserGroup

  -- | Get list of permissions of given group
  listAuthUserGroupPermissions :: AuthUserGroupId -> m [WithId AuthUserGroupPermsId AuthUserGroupPerms]
  default listAuthUserGroupPermissions :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroupId -> m [WithId AuthUserGroupPermsId AuthUserGroupPerms]
  listAuthUserGroupPermissions = lift . listAuthUserGroupPermissions

  -- | Get list of all users of the group
  listAuthUserGroupUsers :: AuthUserGroupId -> m [WithId AuthUserGroupUsersId AuthUserGroupUsers]
  default listAuthUserGroupUsers :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroupId -> m [WithId AuthUserGroupUsersId AuthUserGroupUsers]
  listAuthUserGroupUsers = lift . listAuthUserGroupUsers

  -- | Replace record of user group
  replaceAuthUserGroup :: AuthUserGroupId -> AuthUserGroup -> m ()
  default replaceAuthUserGroup :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroupId -> AuthUserGroup -> m ()
  replaceAuthUserGroup = (lift .) . replaceAuthUserGroup

  -- | Remove all users from group
  clearAuthUserGroupUsers :: AuthUserGroupId -> m ()
  default clearAuthUserGroupUsers :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroupId -> m ()
  clearAuthUserGroupUsers = lift . clearAuthUserGroupUsers

  -- | Remove all permissions from group
  clearAuthUserGroupPerms :: AuthUserGroupId -> m ()
  default clearAuthUserGroupPerms :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroupId -> m ()
  clearAuthUserGroupPerms = lift . clearAuthUserGroupPerms

  -- | Delete user group from storage
  deleteAuthUserGroup :: AuthUserGroupId -> m ()
  default deleteAuthUserGroup :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroupId -> m ()
  deleteAuthUserGroup = lift . deleteAuthUserGroup

  -- | Get paged list of user groups with total count
  listGroupsPaged :: Page -> PageSize -> m ([WithId AuthUserGroupId AuthUserGroup], Word)
  default listGroupsPaged :: (m ~ t n, MonadTrans t, HasStorage n) => Page -> PageSize -> m ([WithId AuthUserGroupId AuthUserGroup], Word)
  listGroupsPaged = (lift .) . listGroupsPaged

  -- | Set group name
  setAuthUserGroupName :: AuthUserGroupId -> Text -> m ()
  default setAuthUserGroupName :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroupId -> Text -> m ()
  setAuthUserGroupName = (lift .) . setAuthUserGroupName

  -- | Set group parent
  setAuthUserGroupParent :: AuthUserGroupId -> Maybe AuthUserGroupId -> m ()
  default setAuthUserGroupParent :: (m ~ t n, MonadTrans t, HasStorage n) => AuthUserGroupId -> Maybe AuthUserGroupId -> m ()
  setAuthUserGroupParent = (lift .) . setAuthUserGroupParent

  -- | Add new single use code
  insertSingleUseCode :: UserSingleUseCode -> m UserSingleUseCodeId
  default insertSingleUseCode :: (m ~ t n, MonadTrans t, HasStorage n) => UserSingleUseCode -> m UserSingleUseCodeId
  insertSingleUseCode = lift . insertSingleUseCode

  -- | Set usage time of the single use code
  setSingleUseCodeUsed :: UserSingleUseCodeId -> Maybe UTCTime -> m ()
  default setSingleUseCodeUsed :: (m ~ t n, MonadTrans t, HasStorage n) => UserSingleUseCodeId -> Maybe UTCTime -> m ()
  setSingleUseCodeUsed = (lift .) . setSingleUseCodeUsed

  -- | Find unused code for the user and expiration time greater than the given time
  getUnusedCode :: SingleUseCode -> UserImplId -> UTCTime -> m (Maybe (WithId UserSingleUseCodeId UserSingleUseCode))
  default getUnusedCode :: (m ~ t n, MonadTrans t, HasStorage n) => SingleUseCode -> UserImplId -> UTCTime -> m (Maybe (WithId UserSingleUseCodeId UserSingleUseCode))
  getUnusedCode suc = (lift .) . getUnusedCode suc

  -- | Invalidate all permanent codes for user and set use time for them
  invalidatePermanentCodes :: UserImplId -> UTCTime -> m ()
  default invalidatePermanentCodes :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> UTCTime -> m ()
  invalidatePermanentCodes = (lift .) . invalidatePermanentCodes

  -- | Select last valid restoration code by the given current time
  selectLastRestoreCode :: UserImplId -> UTCTime -> m (Maybe (WithId UserRestoreId UserRestore))
  default selectLastRestoreCode :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> UTCTime -> m (Maybe (WithId UserRestoreId UserRestore))
  selectLastRestoreCode = (lift .) . selectLastRestoreCode

  -- | Insert new restore code
  insertUserRestore :: UserRestore -> m UserRestoreId
  default insertUserRestore :: (m ~ t n, MonadTrans t, HasStorage n) => UserRestore -> m UserRestoreId
  insertUserRestore = lift . insertUserRestore

  -- | Find unexpired by the time restore code
  findRestoreCode :: UserImplId -> RestoreCode -> UTCTime -> m (Maybe (WithId UserRestoreId UserRestore))
  default findRestoreCode :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> RestoreCode -> UTCTime -> m (Maybe (WithId UserRestoreId UserRestore))
  findRestoreCode uid = (lift .) . findRestoreCode uid

  -- | Replace restore code with new value
  replaceRestoreCode :: UserRestoreId -> UserRestore -> m ()
  default replaceRestoreCode :: (m ~ t n, MonadTrans t, HasStorage n) => UserRestoreId -> UserRestore -> m ()
  replaceRestoreCode = (lift .) . replaceRestoreCode

  -- | Find first non-expired by the time token for user
  findAuthToken :: UserImplId -> UTCTime -> m (Maybe (WithId AuthTokenId AuthToken))
  default findAuthToken :: (m ~ t n, MonadTrans t, HasStorage n) => UserImplId -> UTCTime -> m (Maybe (WithId AuthTokenId AuthToken))
  findAuthToken = (lift .) . findAuthToken

  -- | Find token by value
  findAuthTokenByValue :: SimpleToken -> m (Maybe (WithId AuthTokenId AuthToken))
  default findAuthTokenByValue :: (m ~ t n, MonadTrans t, HasStorage n) => SimpleToken -> m (Maybe (WithId AuthTokenId AuthToken))
  findAuthTokenByValue = lift . findAuthTokenByValue

  -- | Insert new token
  insertAuthToken :: AuthToken -> m AuthTokenId
  default insertAuthToken :: (m ~ t n, MonadTrans t, HasStorage n) => AuthToken -> m AuthTokenId
  insertAuthToken = lift . insertAuthToken

  -- | Replace auth token with new value
  replaceAuthToken :: AuthTokenId -> AuthToken -> m ()
  default replaceAuthToken :: (m ~ t n, MonadTrans t, HasStorage n) => AuthTokenId -> AuthToken -> m ()
  replaceAuthToken = (lift .) . replaceAuthToken

instance HasStorage m => HasStorage (ContT r m)
instance HasStorage m => HasStorage (ExceptT e m)
instance HasStorage m => HasStorage (ReaderT r m)
instance (HasStorage m, Monoid w) => HasStorage (LRWS.RWST r w s m)
instance (HasStorage m, Monoid w) => HasStorage (SRWS.RWST r w s m)
instance HasStorage m => HasStorage (LS.StateT s m)
instance HasStorage m => HasStorage (SS.StateT s m)
instance (HasStorage m, Monoid w) => HasStorage (LW.WriterT w m)
instance (HasStorage m, Monoid w) => HasStorage (SW.WriterT w m)

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

-- | Try to parse a password hash.
readPwHash :: BC.ByteString -> Maybe (Int, BC.ByteString, BC.ByteString)
readPwHash pw | length broken /= 4
                || algorithm /= "sha256"
                || BC.length hash /= 44 = Nothing
              | otherwise = case BC.readInt strBS of
                              Just (strength, _) -> Just (strength, salt, hash)
                              Nothing -> Nothing
    where broken = BC.split '|' pw
          [algorithm, strBS, salt, hash] = broken

-- | Hash password with given strengh, you can pass already hashed password
-- to specified strength
makeHashedPassword :: MonadIO m => Int -> Password -> m Password
makeHashedPassword strength pass =liftIO $ case readPwHash . passToByteString $ pass of
  Nothing ->  fmap byteStringToPass $ makePassword (passToByteString pass) strength
  Just (passStrength, passSalt, passHash) -> if
    | passStrength >= strength -> pure pass
    | otherwise -> pure $ byteStringToPass $ strengthenPassword (passToByteString pass) strength

-- | Creation of new user
createUser :: HasStorage m => Int -> Login -> Password -> Email -> [Permission] -> m UserImplId
createUser strength login pass email perms = do
  pass' <- makeHashedPassword strength pass
  i <- insertUserImpl UserImpl {
      userImplLogin = login
    , userImplPassword = pass'
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
  pass' <- makeHashedPassword strength pass
  return $ user { userImplPassword = pass' }

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
