module Servant.Server.Auth.Token.Acid(
    AcidBackendT
  , runAcidBackendT
  ) where

import Control.Monad.Except
import Control.Monad.Reader
import Data.Acid
import Data.Acid.Core
import Servant.Server
import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.Model

import qualified Servant.Server.Auth.Token.Acid.Schema as S

-- | Monad transformer that implements storage backend
newtype AcidBackendT m a = AcidBackendT { unAcidBackendT :: ReaderT (AuthConfig, AcidState S.Model) (ExceptT ServantErr m) a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadError ServantErr, MonadReader (AuthConfig, AcidState S.Model))

instance Monad m => HasAuthConfig (AcidBackendT m) where
  getAuthConfig = fmap fst $ AcidBackendT ask

-- | Execute backend action with given connection pool.
runAcidBackendT :: AuthConfig -> AcidState S.Model -> AcidBackendT m a -> m (Either ServantErr a)
runAcidBackendT cfg db ma = runExceptT $ runReaderT (unAcidBackendT ma) (cfg, db)

-- | Helper to execute DB actions in backend monad
liftAcidQuery :: (QueryEvent event, MonadIO m, MethodState event ~ S.Model) => event -> AcidBackendT m (EventResult event)
liftAcidQuery e = do
  (_, db) <- ask
  liftIO $ query db e

-- | Helper to execute DB actions in backend monad
liftAcidUpdate :: (UpdateEvent event, MonadIO m, MethodState event ~ S.Model) => event -> AcidBackendT m (EventResult event)
liftAcidUpdate e = do
  (_, db) <- ask
  liftIO $ update db e

instance (MonadIO m) => HasStorage (AcidBackendT m) where
  getUserImpl = liftAcidQuery . S.GetUserImpl
  getUserImplByLogin = liftAcidQuery . S.GetUserImplByLogin
  listUsersPaged page size = liftAcidQuery $ S.ListUsersPaged page size
  getUserImplPermissions = liftAcidQuery . S.GetUserImplPermissions
  deleteUserPermissions = liftAcidUpdate . S.DeleteUserPermissions
  insertUserPerm = liftAcidUpdate . S.InsertUserPerm
  insertUserImpl = liftAcidUpdate . S.InsertUserImpl
  replaceUserImpl i v = liftAcidUpdate $ S.ReplaceUserImpl i v
  deleteUserImpl = liftAcidUpdate . S.DeleteUserImpl
  hasPerm i p = liftAcidQuery $ S.HasPerm i p
  getFirstUserByPerm = liftAcidQuery . S.GetFirstUserByPerm
  selectUserImplGroups = liftAcidQuery . S.SelectUserImplGroups
  clearUserImplGroups = liftAcidUpdate . S.ClearUserImplGroups
  insertAuthUserGroup = liftAcidUpdate . S.InsertAuthUserGroup
  insertAuthUserGroupUsers = liftAcidUpdate . S.InsertAuthUserGroupUsers
  insertAuthUserGroupPerms = liftAcidUpdate . S.InsertAuthUserGroupPerms
  getAuthUserGroup = liftAcidQuery . S.GetAuthUserGroup
  listAuthUserGroupPermissions = liftAcidQuery . S.ListAuthUserGroupPermissions
  listAuthUserGroupUsers = liftAcidQuery . S.ListAuthUserGroupUsers
  replaceAuthUserGroup i v = liftAcidUpdate $ S.ReplaceAuthUserGroup i v
  clearAuthUserGroupUsers = liftAcidUpdate . S.ClearAuthUserGroupUsers
  clearAuthUserGroupPerms = liftAcidUpdate . S.ClearAuthUserGroupPerms
  deleteAuthUserGroup = liftAcidUpdate . S.DeleteAuthUserGroup
  listGroupsPaged page size = liftAcidQuery $ S.ListGroupsPaged page size
  setAuthUserGroupName i n = liftAcidUpdate $ S.SetAuthUserGroupName i n
  setAuthUserGroupParent i mp = liftAcidUpdate $ S.SetAuthUserGroupParent i mp
  insertSingleUseCode = liftAcidUpdate . S.InsertSingleUseCode
  setSingleUseCodeUsed i mt = liftAcidUpdate $ S.SetSingleUseCodeUsed i mt
  getUnusedCode c i t = liftAcidQuery $ S.GetUnusedCode c i t
  invalidatePermamentCodes i t = liftAcidUpdate $ S.InvalidatePermamentCodes i t
  selectLastRestoreCode i t = liftAcidQuery $ S.SelectLastRestoreCode i t
  insertUserRestore = liftAcidUpdate . S.InsertUserRestore
  findRestoreCode i rc t = liftAcidQuery $ S.FindRestoreCode i rc t
  replaceRestoreCode i v = liftAcidUpdate $ S.ReplaceRestoreCode i v
  findAuthToken i t = liftAcidQuery $ S.FindAuthToken i t
  findAuthTokenByValue t = liftAcidQuery $ S.FindAuthTokenByValue t
  insertAuthToken = liftAcidUpdate . S.InsertAuthToken
  replaceAuthToken i v = liftAcidUpdate $ S.ReplaceAuthToken i v
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
