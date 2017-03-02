module Servant.Server.Auth.Token.Acid(
    AcidBackendT
  , runAcidBackendT
  , deriveAcidHasStorage
  ) where

import Control.Monad.Base
import Control.Monad.Except
import Control.Monad.Reader
import Control.Monad.Trans.Control
import Data.Acid
import Data.Acid.Core
import Language.Haskell.TH
import Servant.Server
import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.Model

-- | Monad transformer that implements storage backend
newtype AcidBackendT st m a = AcidBackendT { unAcidBackendT :: ReaderT (AuthConfig, AcidState st) (ExceptT ServantErr m) a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadError ServantErr, MonadReader (AuthConfig, AcidState st))

deriving instance MonadBase IO m => MonadBase IO (AcidBackendT st m)

instance Monad m => HasAuthConfig (AcidBackendT st m) where
  getAuthConfig = fmap fst $ AcidBackendT ask

newtype StMAcidBackendT st m a = StMAcidBackendT { unStMAcidBackendT :: StM (ReaderT (AuthConfig, AcidState st) (ExceptT ServantErr m)) a }

instance MonadBaseControl IO m => MonadBaseControl IO (AcidBackendT st m) where
    type StM (AcidBackendT st m) a = StMAcidBackendT st m a
    liftBaseWith f = AcidBackendT $ liftBaseWith $ \q -> f (fmap StMAcidBackendT . q . unAcidBackendT)
    restoreM = AcidBackendT . restoreM . unStMAcidBackendT

-- | Execute backend action with given connection pool.
runAcidBackendT :: AuthConfig -> AcidState st -> AcidBackendT st m a -> m (Either ServantErr a)
runAcidBackendT cfg db ma = runExceptT $ runReaderT (unAcidBackendT ma) (cfg, db)

-- | Derives acid-state 'HasStorage' instance for functions that are generated in 'makeModelAcidic'.
--
-- Use this as following:
-- @
-- instance HasModelRead MyState where
--   askModel = authModel
--
-- instance HasModelWrite MyState where
--   putModel m v = m { authModel = v }
--
-- makeModelAcidic ''MyState
-- deriveAcidHasStorage
-- @
deriveAcidHasStorage :: Name -> DecsQ
deriveAcidHasStorage globalState = [d|
  -- | Helper to execute DB actions in backend monad
  liftAcidQuery :: (QueryEvent event, MonadIO m, MethodState event ~ $st) => event -> AcidBackendT $st m (EventResult event)
  liftAcidQuery e = do
    (_, db) <- ask
    liftIO $ query db e

  -- | Helper to execute DB actions in backend monad
  liftAcidUpdate :: (UpdateEvent event, MonadIO m, MethodState event ~ $st) => event -> AcidBackendT $st m (EventResult event)
  liftAcidUpdate e = do
    (_, db) <- ask
    liftIO $ update db e

  instance MonadIO m => HasStorage (AcidBackendT $st m) where
    getUserImpl = liftAcidQuery . $(conE $ mkName "GetUserImpl")
    getUserImplByLogin = liftAcidQuery . $(conE $ mkName "GetUserImplByLogin")
    listUsersPaged page size = liftAcidQuery $ $(conE $ mkName "ListUsersPaged") page size
    getUserImplPermissions = liftAcidQuery . $(conE $ mkName "GetUserImplPermissions")
    deleteUserPermissions = liftAcidUpdate . $(conE $ mkName "DeleteUserPermissions")
    insertUserPerm = liftAcidUpdate . $(conE $ mkName "InsertUserPerm")
    insertUserImpl = liftAcidUpdate . $(conE $ mkName "InsertUserImpl")
    replaceUserImpl i v = liftAcidUpdate $ $(conE $ mkName "ReplaceUserImpl") i v
    deleteUserImpl = liftAcidUpdate . $(conE $ mkName "DeleteUserImpl")
    hasPerm i p = liftAcidQuery $ $(conE $ mkName "HasPerm") i p
    getFirstUserByPerm = liftAcidQuery . $(conE $ mkName "GetFirstUserByPerm")
    selectUserImplGroups = liftAcidQuery . $(conE $ mkName "SelectUserImplGroups")
    clearUserImplGroups = liftAcidUpdate . $(conE $ mkName "ClearUserImplGroups")
    insertAuthUserGroup = liftAcidUpdate . $(conE $ mkName "InsertAuthUserGroup")
    insertAuthUserGroupUsers = liftAcidUpdate . $(conE $ mkName "InsertAuthUserGroupUsers")
    insertAuthUserGroupPerms = liftAcidUpdate . $(conE $ mkName "InsertAuthUserGroupPerms")
    getAuthUserGroup = liftAcidQuery . $(conE $ mkName "GetAuthUserGroup")
    listAuthUserGroupPermissions = liftAcidQuery . $(conE $ mkName "ListAuthUserGroupPermissions")
    listAuthUserGroupUsers = liftAcidQuery . $(conE $ mkName "ListAuthUserGroupUsers")
    replaceAuthUserGroup i v = liftAcidUpdate $ $(conE $ mkName "ReplaceAuthUserGroup") i v
    clearAuthUserGroupUsers = liftAcidUpdate . $(conE $ mkName "ClearAuthUserGroupUsers")
    clearAuthUserGroupPerms = liftAcidUpdate . $(conE $ mkName "ClearAuthUserGroupPerms")
    deleteAuthUserGroup = liftAcidUpdate . $(conE $ mkName "DeleteAuthUserGroup")
    listGroupsPaged page size = liftAcidQuery $ $(conE $ mkName "ListGroupsPaged") page size
    setAuthUserGroupName i n = liftAcidUpdate $ $(conE $ mkName "SetAuthUserGroupName") i n
    setAuthUserGroupParent i mp = liftAcidUpdate $ $(conE $ mkName "SetAuthUserGroupParent") i mp
    insertSingleUseCode = liftAcidUpdate . $(conE $ mkName "InsertSingleUseCode")
    setSingleUseCodeUsed i mt = liftAcidUpdate $ $(conE $ mkName "SetSingleUseCodeUsed") i mt
    getUnusedCode c i t = liftAcidQuery $ $(conE $ mkName "GetUnusedCode") c i t
    invalidatePermamentCodes i t = liftAcidUpdate $ $(conE $ mkName "InvalidatePermamentCodes") i t
    selectLastRestoreCode i t = liftAcidQuery $ $(conE $ mkName "SelectLastRestoreCode") i t
    insertUserRestore = liftAcidUpdate . $(conE $ mkName "InsertUserRestore")
    findRestoreCode i rc t = liftAcidQuery $ $(conE $ mkName "FindRestoreCode") i rc t
    replaceRestoreCode i v = liftAcidUpdate $ $(conE $ mkName "ReplaceRestoreCode") i v
    findAuthToken i t = liftAcidQuery $ $(conE $ mkName "FindAuthToken") i t
    findAuthTokenByValue t = liftAcidQuery $ $(conE $ mkName "FindAuthTokenByValue") t
    insertAuthToken = liftAcidUpdate . $(conE $ mkName "InsertAuthToken")
    replaceAuthToken i v = liftAcidUpdate $ $(conE $ mkName "ReplaceAuthToken") i v
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
  |]
  where st = conT globalState
