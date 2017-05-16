{-# OPTIONS_GHC -fno-warn-orphans #-}
module Servant.Server.Auth.Token.RocksDB.Schema where

import Control.Concurrent.RLock
import Control.Lens
import Control.Monad
import Control.Monad.Catch
import Control.Monad.IO.Class
import Control.Monad.Trans.Resource (MonadResource)
import Data.Aeson.WithField
import Data.ByteString (ByteString)
import Data.Int
import Data.List (sort, sortBy)
import Data.Map.Strict (Map)
import Data.Maybe
import Data.Ord
import Data.SafeCopy.Store
import Data.SafeCopy.Store.Internal
import Data.Set (Set)
import Data.Store
import Data.Text (Text)
import Data.Time
import Data.Typeable hiding (Proxy)
import Database.RocksDB
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

import qualified Data.Foldable as F
import qualified Data.Map.Strict as M
import qualified Data.Set as S

-- | ID of global model index
newtype ModelId = ModelId { unModelId :: Int64 }
  deriving (Show, Read, Ord, Eq)

-- | Global id of model index
modelId :: ModelId
modelId = ModelId 0

-- | Holds all data for auth server in acid-state container
data Model = Model {
  -- | Holds users by id
  _modelUsers                    :: !(Set UserImplId)
  -- | Holds users by login (same content as 'modelUsers')
, _modelUsersByLogin             :: !(Map Login UserImplId)
  -- | Holds 'UserPerm'
, _modelUserPerms                :: !(Set UserPermId)
  -- | Holds 'AuthToken'
, _modelAuthTokens               :: !(Set AuthTokenId)
  -- | Holds 'UserRestore'
, _modelUserRestores             :: !(Set UserRestoreId)
  -- | Holds 'UserSingleUseCode'
, _modelUserSingleUseCodes       :: !(Set UserSingleUseCodeId)
  -- | Holds 'AuthUserGroup'
, _modelAuthUserGroups           :: !(Set AuthUserGroupId)
  -- | Holds 'AuthUserGroupUsers'
, _modelAuthUserGroupUsers       :: !(Set AuthUserGroupUsersId)
  -- | Holds 'AuthUserGroupPerms'
, _modelAuthUserGroupPerms       :: !(Set AuthUserGroupPermsId)
  -- | Holds next id for entities
, _modelNextUserImplId           :: !Int64
-- | Holds next id for entities
, _modelNextUserPermId           :: !Int64
-- | Holds next id for entities
, _modelNextAuthTokenId          :: !Int64
-- | Holds next id for entities
, _modelNextUserRestoreId        :: !Int64
-- | Holds next id for entities
, _modelNextUserSingleUseCodeId  :: !Int64
-- | Holds next id for entities
, _modelNextAuthUserGroupId      :: !Int64
-- | Holds next id for entities
, _modelNextAuthUserGroupUserId  :: !Int64
-- | Holds next id for entities
, _modelNextAuthUserGroupPermId  :: !Int64
}

makeLenses ''Model

-- | Defines empty model for new database
newModel :: Model
newModel = Model {
    _modelUsers = mempty
  , _modelUsersByLogin = mempty
  , _modelUserPerms = mempty
  , _modelAuthTokens = mempty
  , _modelUserRestores = mempty
  , _modelUserSingleUseCodes = mempty
  , _modelAuthUserGroups = mempty
  , _modelAuthUserGroupUsers = mempty
  , _modelAuthUserGroupPerms = mempty
  , _modelNextUserImplId = 0
  , _modelNextUserPermId = 0
  , _modelNextAuthTokenId = 0
  , _modelNextUserRestoreId = 0
  , _modelNextUserSingleUseCodeId = 0
  , _modelNextAuthUserGroupId = 0
  , _modelNextAuthUserGroupUserId = 0
  , _modelNextAuthUserGroupPermId = 0
  }

-- | Helper that defines bijection between key and record
class Key i a | i -> a, a -> i where
  encodeKey :: i -> ByteString

  default encodeKey :: (SafeCopy i, Typeable i) => i -> ByteString
  encodeKey i = runEncode $ do
    _ <- pokeE tname
    safePut i
    where
      tname = show $ typeRep (Proxy :: Proxy i)

instance Key AuthTokenId AuthToken
instance Key AuthUserGroupId AuthUserGroup
instance Key AuthUserGroupPermsId AuthUserGroupPerms
instance Key AuthUserGroupUsersId AuthUserGroupUsers
instance Key ModelId Model
instance Key UserImplId UserImpl
instance Key UserPermId UserPerm
instance Key UserRestoreId UserRestore
instance Key UserSingleUseCodeId UserSingleUseCode

-- | Holds together db reference and options for read/write and mutex
data RocksDBEnv = RocksDBEnv !DB !ReadOptions !WriteOptions !RLock

-- | Make new environment for execution of RocksDB operations
newRocksDBEnv :: MonadIO m => DB -> ReadOptions -> WriteOptions -> m RocksDBEnv
newRocksDBEnv db rops wopts = do
  rlock <- liftIO new
  return $ RocksDBEnv db rops wopts rlock

-- | Load object by id from leveldb
load :: (MonadResource m, Key i a, SafeCopy a) => RocksDBEnv -> i -> m (Maybe a)
load (RocksDBEnv db ropts _ _) i = do
  mbs <- get db ropts (encodeKey i)
  return $ decodeExWith safeGet <$> mbs

-- | Store object by id in leveldb
store :: (MonadResource m, Key i a, SafeCopy a) => RocksDBEnv -> i -> a -> m ()
store (RocksDBEnv db _ wopts _) i a = put db wopts (encodeKey i) (runEncode $ safePut a)

-- | Remove object by given id in leveldb
remove :: (MonadResource m, Key i a) => RocksDBEnv -> i -> m ()
remove (RocksDBEnv db _ wopts _) i = delete db wopts (encodeKey i)

-- | Modify value by id in leveldb
modify :: (MonadResource m, MonadMask m, Key i a, SafeCopy a) => RocksDBEnv -> i -> (a -> a) -> m ()
modify db@(RocksDBEnv _ _ _ mut) i f = bracket_ (liftIO $ acquire mut) (liftIO $ release mut) $ do
  ma <- load db i
  case ma of
    Nothing -> return ()
    Just a -> store db i (f a)

-- | Modify value by id in leveldb
modifyM :: (MonadResource m, MonadMask m, Key i a, SafeCopy a) => RocksDBEnv -> i -> (a -> m a) -> m ()
modifyM db@(RocksDBEnv _ _ _ mut) i f = bracket_ (liftIO $ acquire mut) (liftIO $ release mut) $ do
  ma <- load db i
  case ma of
    Nothing -> return ()
    Just a -> store db i =<< f a

-- | Load global index from leveldb
loadModel :: MonadResource m => RocksDBEnv -> m Model
loadModel db = do
  mm <- load db modelId
  return $ fromMaybe newModel mm

-- | Store glogal index to leveldb
storeModel :: MonadResource m => RocksDBEnv -> Model -> m ()
storeModel db = store db modelId

-- | Modify global index
modifyModel :: MonadResource m => RocksDBEnv -> (Model -> Model) -> m ()
modifyModel db f = do
  m <- loadModel db
  storeModel db $ f m

-- | Modify global index
modifyModelM :: (MonadResource m, MonadMask m) => RocksDBEnv -> (Model -> m (Model, a)) -> m a
modifyModelM db@(RocksDBEnv _ _ _ mut) f = bracket_ (liftIO $ acquire mut) (liftIO $ release mut) $ do
  m <- loadModel db
  (m', a) <- f m
  storeModel db m'
  return a

-- | Helper to get paged list of entities
getPagedList :: (MonadResource m, Ord i, Key i a, SafeCopy a) => RocksDBEnv -> Page -> PageSize -> Set i -> m ([WithId i a], Word)
getPagedList db p s is = do
  let is' = take (fromIntegral s) . drop (fromIntegral $ p * s) . sort . F.toList $ is
  es <- traverse (\i -> fmap (i,) <$> load db i) is'
  return (fmap (uncurry WithField) . catMaybes $ es, fromIntegral $ F.length is)

-- | Generic way to insert record in the leveldb with track in global registry
insertRecord :: (MonadResource m, MonadMask m, Key i a, ConvertableKey i, Ord i, SafeCopy a)
  => Lens' Model Int64 -- ^ Field of model that store counter of the record ids
  -> Lens' Model (Set i) -- ^ Field of model that store a registry of the record ids
  -> a -> RocksDBEnv -> m i
insertRecord counterL registryL v db = modifyModelM db $ \m -> do
  let
    i = toKey $ view counterL m
    m' = m & over counterL (+1)
           & over registryL (S.insert i)
  store db i v
  return (m', i)

-- | Generic way to select all records that satisfies given predicate
selectRecords :: (MonadResource m, Key i a, SafeCopy a)
  => Lens' Model (Set i) -- ^ Model field with registry of the records
  -> (i -> a -> Bool) -- ^ Predicate
  -> RocksDBEnv -> m [WithId i a]
selectRecords registryL f db = do
  is <- view registryL <$> loadModel db
  fmap catMaybes $ forM (F.toList is) $ \i -> do
    ma <- load db i
    return $ case ma of
      Just a | f i a -> Just $ WithField i a
      _ -> Nothing

-- | Generic way to delete several records with respect of global registry
deleteRecords :: (MonadResource m, MonadMask m, Key i a, Ord i, Foldable f)
  => Lens' Model (Set i) -- ^ Model field with registry of the records
  -> f i -- ^ Set of ids of records that should be deleted
  -> RocksDBEnv -> m ()
deleteRecords registryL is db = modifyModelM db $ \m -> do
  F.traverse_ (remove db) is
  return . (, ()) $ m & over registryL (`S.difference` (S.fromList . F.toList) is)

-- | Generic way to replace record in registry and leveldb
replaceRecord :: (MonadResource m, MonadMask m, Key i a, Ord i, SafeCopy a)
  => Lens' Model (Set i) -- ^ Model field with registry of the records
  -> i -- ^ ID of record
  -> a -- ^ Value of record
  -> RocksDBEnv -> m ()
replaceRecord registryL i v db = modifyModelM db $ \m -> do
  store db i v
  return . (, ()) $ m & over registryL (S.insert i)

-- | Extract id
withId :: WithField s i a -> i
withId (WithField i _) = i

-- | Extract value
withVal :: WithField s i a -> a
withVal (WithField _ v) = v

--------------------------------------------------------------------------------
-- End of generic helpers
--------------------------------------------------------------------------------

-- | Getting user from storage by login
getUserImplByLogin :: MonadResource m => Login -> RocksDBEnv -> m (Maybe (WithId UserImplId UserImpl))
getUserImplByLogin login db = do
  Model{..} <- loadModel db
  case M.lookup login _modelUsersByLogin of
    Nothing -> return Nothing
    Just i -> fmap (WithField i) <$> load db i

-- | Get paged list of users and total count of users
listUsersPaged :: MonadResource m => Page -> PageSize -> RocksDBEnv -> m ([WithId UserImplId UserImpl], Word)
listUsersPaged p s db = getPagedList db p s =<< (_modelUsers <$> loadModel db)

-- | Get user permissions, ascending by tag
getUserImplPermissions :: MonadResource m => UserImplId -> RocksDBEnv -> m [WithId UserPermId UserPerm]
getUserImplPermissions i = selectRecords modelUserPerms $ \ _ perm -> userPermUser perm == i

-- | Delete user permissions
deleteUserPermissions :: (MonadResource m, MonadMask m) => UserImplId -> RocksDBEnv -> m ()
deleteUserPermissions i db = do
  is <- fmap withId <$> getUserImplPermissions i db
  deleteRecords modelUserPerms is db

-- | Insertion of new user permission
insertUserPerm :: (MonadResource m, MonadMask m) => UserPerm -> RocksDBEnv -> m UserPermId
insertUserPerm = insertRecord modelNextUserPermId modelUserPerms

-- | Insertion of new user
insertUserImpl :: (MonadResource m, MonadMask m) => UserImpl -> RocksDBEnv -> m UserImplId
insertUserImpl v db = modifyModelM db $ \m -> do
  let
    i = toKey $ view modelNextUserImplId m
    m' = m & over modelNextUserImplId (+1)
           & over modelUsers (S.insert i)
           & over modelUsersByLogin (M.insert (userImplLogin v) i)
  store db i v
  return (m', i)

-- | Replace user with new value
replaceUserImpl :: (MonadResource m, MonadMask m) => UserImplId -> UserImpl -> RocksDBEnv -> m ()
replaceUserImpl i v db = modifyModelM db $ \m -> do
  muser <- load db i
  let cleanOld = case muser of
        Nothing -> id
        Just v' -> M.delete (userImplLogin v')
  store db i v
  return . (, ()) $ m & over modelUsersByLogin (M.insert (userImplLogin v) i . cleanOld)

-- | Delete user by id
deleteUserImpl :: (MonadResource m, MonadMask m) => UserImplId -> RocksDBEnv -> m ()
deleteUserImpl i db = do
  muser <- load db i
  case muser of
    Nothing -> return ()
    Just u  -> modifyModelM db $ \m -> do
      deleteUserPermissions i db
      remove db i
      return . (, ()) $ m
        & over modelUsers (S.delete i)
        & over modelUsersByLogin (M.delete (userImplLogin u))


-- | Check whether the user has particular permission
hasPerm :: MonadResource m => UserImplId -> Permission -> RocksDBEnv -> m Bool
hasPerm i p db = do
  ps <- getUserImplPermissions i db
  return $ (> 0) . F.length . filter (\(WithField _ p') -> userPermUser p' == i && userPermPermission p' == p) $ ps

-- | Get any user with given permission
getFirstUserByPerm :: MonadResource m => Permission -> RocksDBEnv -> m (Maybe (WithId UserImplId UserImpl))
getFirstUserByPerm perm db = do
  ps <- view modelUserPerms <$> loadModel db
  let
    go _ v@Just{} = pure v
    go i Nothing  = do
      mp <- load db i
      case mp of
        Just p | userPermPermission p == perm -> fmap (WithField (userPermUser p)) <$> load db (userPermUser p)
        _ -> pure Nothing
  F.foldrM go Nothing ps

-- | Select user groups and sort them by ascending name
selectUserImplGroups :: MonadResource m => UserImplId -> RocksDBEnv -> m [WithId AuthUserGroupUsersId AuthUserGroupUsers]
selectUserImplGroups i = selectRecords modelAuthUserGroupUsers $ \_ g -> authUserGroupUsersUser g == i

-- | Remove user from all groups
clearUserImplGroups :: (MonadResource m, MonadMask m) => UserImplId -> RocksDBEnv -> m ()
clearUserImplGroups i db = do
  is <- fmap withId <$> selectUserImplGroups i db
  deleteRecords modelAuthUserGroupUsers is db

-- | Add new user group
insertAuthUserGroup :: (MonadResource m, MonadMask m) => AuthUserGroup -> RocksDBEnv -> m AuthUserGroupId
insertAuthUserGroup = insertRecord modelNextAuthUserGroupId modelAuthUserGroups

-- | Add user to given group
insertAuthUserGroupUsers :: (MonadResource m, MonadMask m) => AuthUserGroupUsers -> RocksDBEnv -> m AuthUserGroupUsersId
insertAuthUserGroupUsers = insertRecord modelNextAuthUserGroupUserId modelAuthUserGroupUsers

-- | Add permission to given group
insertAuthUserGroupPerms :: (MonadResource m, MonadMask m) => AuthUserGroupPerms -> RocksDBEnv -> m AuthUserGroupPermsId
insertAuthUserGroupPerms = insertRecord modelNextAuthUserGroupPermId modelAuthUserGroupPerms

-- | Get list of permissions of given group
listAuthUserGroupPermissions :: MonadResource m => AuthUserGroupId -> RocksDBEnv -> m [WithId AuthUserGroupPermsId AuthUserGroupPerms]
listAuthUserGroupPermissions i = selectRecords modelAuthUserGroupPerms $ \_ p -> authUserGroupPermsGroup p == i

-- | Get list of all users of the group
listAuthUserGroupUsers :: MonadResource m => AuthUserGroupId -> RocksDBEnv -> m [WithId AuthUserGroupUsersId AuthUserGroupUsers]
listAuthUserGroupUsers i = selectRecords modelAuthUserGroupUsers $ \_ p -> authUserGroupUsersGroup p == i

-- | Replace record of user group
replaceAuthUserGroup :: (MonadResource m, MonadMask m) => AuthUserGroupId -> AuthUserGroup -> RocksDBEnv -> m ()
replaceAuthUserGroup = replaceRecord modelAuthUserGroups

-- | Remove all users from group
clearAuthUserGroupUsers :: (MonadResource m, MonadMask m) => AuthUserGroupId -> RocksDBEnv -> m ()
clearAuthUserGroupUsers i db = do
  is <- fmap withId <$> listAuthUserGroupUsers i db
  deleteRecords modelAuthUserGroupUsers is db

-- | Remove all permissions from group
clearAuthUserGroupPerms :: (MonadResource m, MonadMask m) => AuthUserGroupId -> RocksDBEnv -> m ()
clearAuthUserGroupPerms i db = do
  is <- fmap withId <$> listAuthUserGroupPermissions i db
  deleteRecords modelAuthUserGroupPerms is db

-- | Delete user group from storage
deleteAuthUserGroup :: (MonadResource m, MonadMask m) => AuthUserGroupId -> RocksDBEnv -> m ()
deleteAuthUserGroup i db = modifyModelM db $ \m -> do
  clearAuthUserGroupUsers i db
  clearAuthUserGroupPerms i db
  remove db i
  return . (, ()) $ m & over modelAuthUserGroups (S.delete i)

-- | Get paged list of user groups with total count
listGroupsPaged :: MonadResource m => Page -> PageSize -> RocksDBEnv -> m ([WithId AuthUserGroupId AuthUserGroup], Word)
listGroupsPaged p s db = getPagedList db p s =<< (view modelAuthUserGroups <$> loadModel db)

-- | Set group name
setAuthUserGroupName :: (MonadResource m, MonadMask m) => AuthUserGroupId -> Text -> RocksDBEnv -> m ()
setAuthUserGroupName i n db = modify db i $ \v -> v { authUserGroupName = n }

-- | Set group parent
setAuthUserGroupParent :: (MonadResource m, MonadMask m) => AuthUserGroupId -> Maybe AuthUserGroupId -> RocksDBEnv -> m ()
setAuthUserGroupParent i p db = modify db i $ \v -> v { authUserGroupParent = p }

-- | Add new single use code
insertSingleUseCode :: (MonadResource m, MonadMask m) => UserSingleUseCode -> RocksDBEnv -> m UserSingleUseCodeId
insertSingleUseCode = insertRecord modelNextUserSingleUseCodeId modelUserSingleUseCodes

-- | Set usage time of the single use code
setSingleUseCodeUsed :: (MonadResource m, MonadMask m) => UserSingleUseCodeId -> Maybe UTCTime -> RocksDBEnv -> m ()
setSingleUseCodeUsed i mt db = modify db i $ \v -> v { userSingleUseCodeUsed = mt }

-- | Find unused code for the user and expiration time greater than the given time
getUnusedCode :: MonadResource m => SingleUseCode -> UserImplId -> UTCTime -> RocksDBEnv -> m (Maybe (WithId UserSingleUseCodeId UserSingleUseCode))
getUnusedCode c i t db = headMay . sorting <$> selectRecords modelUserSingleUseCodes f db
  where
    sorting = sortBy (comparing $ Down . userSingleUseCodeExpire . (\(WithField _ v) -> v))
    f _ usc =
      userSingleUseCodeValue usc == c
      && userSingleUseCodeUser usc == i
      && isNothing (userSingleUseCodeUsed usc)
      && (isNothing (userSingleUseCodeExpire usc) || userSingleUseCodeExpire usc >= Just t)

-- | Invalidate all permament codes for user and set use time for them
invalidatePermamentCodes :: (MonadResource m, MonadMask m) => UserImplId -> UTCTime -> RocksDBEnv -> m ()
invalidatePermamentCodes i t db = do
  cs <- view modelUserSingleUseCodes <$> loadModel db
  forM_ (F.toList cs) $ \cid -> do
    mc <- load db cid
    case mc of
      Just usc | isPermament usc -> modify db cid invalidate
      _ -> return ()
  where
    invalidate su = su { userSingleUseCodeUsed = Just t }
    isPermament usc =
         userSingleUseCodeUser usc == i
      && isNothing (userSingleUseCodeUsed usc)
      && isNothing (userSingleUseCodeExpire usc)

-- | Select last valid restoration code by the given current time
selectLastRestoreCode :: MonadResource m => UserImplId -> UTCTime -> RocksDBEnv -> m (Maybe (WithId UserRestoreId UserRestore))
selectLastRestoreCode i t db = headMay . sorting <$> selectRecords modelUserRestores (const f) db
  where
    sorting = sortBy (comparing $ Down . userRestoreExpire . withVal)
    f ur = userRestoreUser ur == i && userRestoreExpire ur > t

-- | Insert new restore code
insertUserRestore :: (MonadResource m, MonadMask m) => UserRestore -> RocksDBEnv -> m UserRestoreId
insertUserRestore = insertRecord modelNextUserRestoreId modelUserRestores

-- | Find unexpired by the time restore code
findRestoreCode :: MonadResource m => UserImplId -> RestoreCode -> UTCTime -> RocksDBEnv -> m (Maybe (WithId UserRestoreId UserRestore))
findRestoreCode i rc t db = headMay . sorting <$> selectRecords modelUserRestores (const f) db
  where
    sorting = sortBy (comparing $ Down . userRestoreExpire . (\(WithField _ v) -> v ))
    f ur = userRestoreUser ur == i && userRestoreValue ur == rc && userRestoreExpire ur > t

-- | Replace restore code with new value
replaceRestoreCode :: (MonadResource m, MonadMask m) => UserRestoreId -> UserRestore ->  RocksDBEnv -> m ()
replaceRestoreCode = replaceRecord modelUserRestores

-- | Find first non-expired by the time token for user
findAuthToken :: MonadResource m => UserImplId -> UTCTime -> RocksDBEnv -> m (Maybe (WithId AuthTokenId AuthToken))
findAuthToken i t db = headMay <$> selectRecords modelAuthTokens (const f) db
  where
    f atok = authTokenUser atok == i && authTokenExpire atok > t

-- | Find token by value
findAuthTokenByValue :: MonadResource m => SimpleToken -> RocksDBEnv -> m (Maybe (WithId AuthTokenId AuthToken))
findAuthTokenByValue v db = headMay <$> selectRecords modelAuthTokens (const f) db
  where
    f atok = authTokenValue atok == v

-- | Insert new token
insertAuthToken :: (MonadResource m, MonadMask m) => AuthToken -> RocksDBEnv -> m AuthTokenId
insertAuthToken = insertRecord modelNextAuthTokenId modelAuthTokens

-- | Replace auth token with new value
replaceAuthToken :: (MonadResource m, MonadMask m) => AuthTokenId -> AuthToken -> RocksDBEnv -> m ()
replaceAuthToken = replaceRecord modelAuthTokens

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
deriveSafeCopy 0 'base ''ModelId
deriveSafeCopy 0 'base ''Model

instance (SafeCopy k, SafeCopy v) => SafeCopy (WithField i k v) where
  putCopy a@(WithField k v) = contain $ do
    _ <- safePut k
    _ <- safePut v
    return a
  getCopy = contain $ WithField
    <$> safeGet
    <*> safeGet
