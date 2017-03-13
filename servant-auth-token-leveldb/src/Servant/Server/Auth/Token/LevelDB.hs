module Servant.Server.Auth.Token.LevelDB(
    LevelDBBackendT
  , runLevelDBBackendT
  , LevelDBEnv
  , newLevelDBEnv
  ) where

import Control.Monad.Base
import Control.Monad.Catch
import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.Trans.Control
import Control.Monad.Trans.Resource
import Servant.Server
import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.LevelDB.Schema (LevelDBEnv, newLevelDBEnv)
import Servant.Server.Auth.Token.Model

import qualified Servant.Server.Auth.Token.LevelDB.Schema as S

-- | Monad transformer that implements storage backend
newtype LevelDBBackendT m a = LevelDBBackendT { unLevelDBBackendT :: ReaderT (AuthConfig, LevelDBEnv) (ExceptT ServantErr (ResourceT m)) a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadError ServantErr, MonadReader (AuthConfig, LevelDBEnv), MonadThrow, MonadCatch)

deriving instance MonadBase IO m => MonadBase IO (LevelDBBackendT m)
deriving instance (MonadBase IO m, MonadThrow m, MonadIO m) => MonadResource (LevelDBBackendT m)

instance Monad m => HasAuthConfig (LevelDBBackendT m) where
  getAuthConfig = fst <$> LevelDBBackendT ask

newtype StMLevelDBBackendT m a = StMLevelDBBackendT { unStMLevelDBBackendT :: StM (ReaderT (AuthConfig, LevelDBEnv) (ExceptT ServantErr m)) a }

instance MonadBaseControl IO m => MonadBaseControl IO (LevelDBBackendT m) where
    type StM (LevelDBBackendT m) a = StMLevelDBBackendT m a
    liftBaseWith f = LevelDBBackendT $ liftBaseWith $ \q -> f (fmap StMLevelDBBackendT . q . unLevelDBBackendT)
    restoreM = LevelDBBackendT . restoreM . unStMLevelDBBackendT

-- | Execute backend action with given connection pool.
runLevelDBBackendT :: MonadBaseControl IO m => AuthConfig -> LevelDBEnv -> LevelDBBackendT m a -> m (Either ServantErr a)
runLevelDBBackendT cfg db ma = runResourceT . runExceptT $ runReaderT (unLevelDBBackendT ma) (cfg, db)

-- | Helper to extract LevelDB reference
getEnv :: Monad m => LevelDBBackendT m LevelDBEnv
getEnv  = snd <$> LevelDBBackendT ask

-- | Helper to lift low-level LevelDB queries to backend monad
liftEnv :: Monad m => (LevelDBEnv -> ResourceT m a) -> LevelDBBackendT m a
liftEnv f = do
  e <- getEnv
  LevelDBBackendT . lift . lift $ f e

instance (MonadBase IO m, MonadIO m, MonadThrow m, MonadMask m) => HasStorage (LevelDBBackendT m) where
  getUserImpl = liftEnv . flip S.load
  getUserImplByLogin = liftEnv . S.getUserImplByLogin
  listUsersPaged page size = liftEnv $ S.listUsersPaged page size
  getUserImplPermissions = liftEnv . S.getUserImplPermissions
  deleteUserPermissions = liftEnv . S.deleteUserPermissions
  insertUserPerm = liftEnv . S.insertUserPerm
  insertUserImpl = liftEnv . S.insertUserImpl
  replaceUserImpl i v = liftEnv $ S.replaceUserImpl i v
  deleteUserImpl = liftEnv . S.deleteUserImpl
  hasPerm i p = liftEnv $ S.hasPerm i p
  getFirstUserByPerm = liftEnv . S.getFirstUserByPerm
  selectUserImplGroups = liftEnv . S.selectUserImplGroups
  clearUserImplGroups = liftEnv . S.clearUserImplGroups
  insertAuthUserGroup = liftEnv . S.insertAuthUserGroup
  insertAuthUserGroupUsers = liftEnv . S.insertAuthUserGroupUsers
  insertAuthUserGroupPerms = liftEnv . S.insertAuthUserGroupPerms
  getAuthUserGroup = liftEnv . flip S.load
  listAuthUserGroupPermissions = liftEnv . S.listAuthUserGroupPermissions
  listAuthUserGroupUsers = liftEnv . S.listAuthUserGroupUsers
  replaceAuthUserGroup i v = liftEnv $ S.replaceAuthUserGroup i v
  clearAuthUserGroupUsers = liftEnv . S.clearAuthUserGroupUsers
  clearAuthUserGroupPerms = liftEnv . S.clearAuthUserGroupPerms
  deleteAuthUserGroup = liftEnv . S.deleteAuthUserGroup
  listGroupsPaged page size = liftEnv $ S.listGroupsPaged page size
  setAuthUserGroupName i n = liftEnv $ S.setAuthUserGroupName i n
  setAuthUserGroupParent i mp = liftEnv $ S.setAuthUserGroupParent i mp
  insertSingleUseCode = liftEnv . S.insertSingleUseCode
  setSingleUseCodeUsed i mt = liftEnv $ S.setSingleUseCodeUsed i mt
  getUnusedCode c i t = liftEnv $ S.getUnusedCode c i t
  invalidatePermamentCodes i t = liftEnv $ S.invalidatePermamentCodes i t
  selectLastRestoreCode i t = liftEnv $ S.selectLastRestoreCode i t
  insertUserRestore = liftEnv . S.insertUserRestore
  findRestoreCode i rc t = liftEnv $ S.findRestoreCode i rc t
  replaceRestoreCode i v = liftEnv $ S.replaceRestoreCode i v
  findAuthToken i t = liftEnv $ S.findAuthToken i t
  findAuthTokenByValue t = liftEnv $ S.findAuthTokenByValue t
  insertAuthToken = liftEnv . S.insertAuthToken
  replaceAuthToken i v = liftEnv $ S.replaceAuthToken i v
  {-# INLINE getUserImpl #-}
  {-# INLINE getUserImplByLogin #-}
  {-# INLINE listUsersPaged #-}
  {-# INLINE getUserImplPermissions #-}
  {-# INLINE deleteUserPermissions #-}
  {-# INLINE insertUserPerm #-}
  {-# INLINE insertUserImpl #-}
  {-# INLINE replaceUserImpl #-}
  {-# INLINE deleteUserImpl #-}
  {-# INLINE hasPerm #-}
  {-# INLINE getFirstUserByPerm #-}
  {-# INLINE selectUserImplGroups #-}
  {-# INLINE clearUserImplGroups #-}
  {-# INLINE insertAuthUserGroup #-}
  {-# INLINE insertAuthUserGroupUsers #-}
  {-# INLINE insertAuthUserGroupPerms #-}
  {-# INLINE getAuthUserGroup #-}
  {-# INLINE listAuthUserGroupPermissions #-}
  {-# INLINE listAuthUserGroupUsers #-}
  {-# INLINE replaceAuthUserGroup #-}
  {-# INLINE clearAuthUserGroupUsers #-}
  {-# INLINE clearAuthUserGroupPerms #-}
  {-# INLINE deleteAuthUserGroup #-}
  {-# INLINE listGroupsPaged #-}
  {-# INLINE setAuthUserGroupName #-}
  {-# INLINE setAuthUserGroupParent #-}
  {-# INLINE insertSingleUseCode #-}
  {-# INLINE setSingleUseCodeUsed #-}
  {-# INLINE getUnusedCode #-}
  {-# INLINE invalidatePermamentCodes #-}
  {-# INLINE selectLastRestoreCode #-}
  {-# INLINE insertUserRestore #-}
  {-# INLINE findRestoreCode #-}
  {-# INLINE replaceRestoreCode #-}
  {-# INLINE findAuthToken #-}
  {-# INLINE findAuthTokenByValue #-}
  {-# INLINE insertAuthToken #-}
  {-# INLINE replaceAuthToken #-}
