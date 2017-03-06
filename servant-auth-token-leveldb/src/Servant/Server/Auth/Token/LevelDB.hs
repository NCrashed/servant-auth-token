module Servant.Server.Auth.Token.LevelDB(
    LevelDBBackendT
  , runLevelDBBackendT
  , LevelDBEnv
  , newLevelDBEnv
  ) where

import Control.Monad.Base
import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.Trans.Control
import Servant.Server
import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.LevelDB.Schema
import Servant.Server.Auth.Token.Model
import Database.LevelDB

-- | Monad transformer that implements storage backend
newtype LevelDBBackendT m a = LevelDBBackendT { unLevelDBBackendT :: ReaderT (AuthConfig, LevelDBEnv) (ExceptT ServantErr m) a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadError ServantErr, MonadReader (AuthConfig, LevelDBEnv))

deriving instance MonadBase IO m => MonadBase IO (LevelDBBackendT m)

instance Monad m => HasAuthConfig (LevelDBBackendT m) where
  getAuthConfig = fst <$> LevelDBBackendT ask

newtype StMLevelDBBackendT m a = StMLevelDBBackendT { unStMLevelDBBackendT :: StM (ReaderT (AuthConfig, LevelDBEnv) (ExceptT ServantErr m)) a }

instance MonadBaseControl IO m => MonadBaseControl IO (LevelDBBackendT m) where
    type StM (LevelDBBackendT m) a = StMLevelDBBackendT m a
    liftBaseWith f = LevelDBBackendT $ liftBaseWith $ \q -> f (fmap StMLevelDBBackendT . q . unLevelDBBackendT)
    restoreM = LevelDBBackendT . restoreM . unStMLevelDBBackendT

-- | Execute backend action with given connection pool.
runLevelDBBackendT :: AuthConfig -> LevelDBEnv -> LevelDBBackendT m a -> m (Either ServantErr a)
runLevelDBBackendT cfg db ma = runExceptT $ runReaderT (unLevelDBBackendT ma) (cfg, db)

instance MonadIO m => HasStorage (LevelDBBackendT m) where
  getUserImpl = undefined
  getUserImplByLogin = undefined
  listUsersPaged page size = undefined
  getUserImplPermissions = undefined
  deleteUserPermissions = undefined
  insertUserPerm = undefined
  insertUserImpl = undefined
  replaceUserImpl i v = undefined
  deleteUserImpl = undefined
  hasPerm i p = undefined
  getFirstUserByPerm = undefined
  selectUserImplGroups = undefined
  clearUserImplGroups = undefined
  insertAuthUserGroup = undefined
  insertAuthUserGroupUsers = undefined
  insertAuthUserGroupPerms = undefined
  getAuthUserGroup = undefined
  listAuthUserGroupPermissions = undefined
  listAuthUserGroupUsers = undefined
  replaceAuthUserGroup i v = undefined
  clearAuthUserGroupUsers = undefined
  clearAuthUserGroupPerms = undefined
  deleteAuthUserGroup = undefined
  listGroupsPaged page size = undefined
  setAuthUserGroupName i n = undefined
  setAuthUserGroupParent i mp = undefined
  insertSingleUseCode = undefined
  setSingleUseCodeUsed i mt = undefined
  getUnusedCode c i t = undefined
  invalidatePermamentCodes i t = undefined
  selectLastRestoreCode i t = undefined
  insertUserRestore = undefined
  findRestoreCode i rc t = undefined
  replaceRestoreCode i v = undefined
  findAuthToken i t = undefined
  findAuthTokenByValue t = undefined
  insertAuthToken = undefined
  replaceAuthToken i v = undefined
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
