module Servant.Server.Auth.Token.Persistent(
    PersistentBackendT
  , runPersistentBackendT
  ) where

import Control.Monad.Reader
import Control.Monad.Trans.Control
import Control.Monad.Except
import Data.Aeson.WithField
import Database.Persist
import Database.Persist.Sql
import Servant.Server
import Servant.Server.Auth.Token.Monad
import Servant.Server.Auth.Token.Model
import Servant.Server.Auth.Token.Config

import qualified Servant.Server.Auth.Token.Persistent.Schema as S

-- | Monad transformer that implements storage backend
newtype PersistentBackendT m a = PersistentBackendT { unPersistentBackendT :: ReaderT (AuthConfig, ConnectionPool) (ExceptT ServantErr (SqlPersistT m)) a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadError ServantErr)

instance Monad m => HasAuthConfig (PersistentBackendT m) where
  getAuthConfig = PersistentBackendT $ asks fst

-- | Execute backend action with given connection pool.
runPersistentBackendT :: MonadBaseControl IO m => AuthConfig -> ConnectionPool -> PersistentBackendT m a -> m (Either ServantErr a)
runPersistentBackendT cfg pool ma = runSqlPool (runExceptT $ runReaderT (unPersistentBackendT ma) (cfg, pool)) pool

-- | Convert entity struct to 'WithId' version
toWithId :: (S.ConvertStorage a' a, S.ConvertStorage (Key a') i) => Entity a' -> WithId i a
toWithId (Entity k v) = WithField (S.convertFrom k) (S.convertFrom v)

-- | Helper to execute DB actions in backend monad
liftDB :: Monad m => SqlPersistT m a -> PersistentBackendT m a
liftDB = PersistentBackendT . lift . lift

instance (MonadIO m) => HasStorage (PersistentBackendT m) where
  getUserImpl = liftDB . fmap (fmap S.convertFrom) . get . S.convertTo
  getUserImplByLogin = liftDB . fmap (fmap toWithId) . getBy . S.UniqueLogin
  listUsersPaged page size = liftDB $ do
    users <- selectList [] [Asc S.UserImplId, OffsetBy (fromIntegral $ page * size), LimitTo (fromIntegral size)]
    total <- count ([] :: [Filter S.UserImpl])
    return (fmap toWithId users, fromIntegral total)
  getUserImplPermissions uid = liftDB . fmap (fmap toWithId) $ selectList [S.UserPermUser ==. S.convertTo uid] [Asc S.UserPermPermission]
  deleteUserPermissions uid = liftDB $ deleteWhere [S.UserPermUser ==. S.convertTo uid]
  insertUserPerm = liftDB . fmap S.convertFrom . insert . S.convertTo
  insertUserImpl = liftDB . fmap S.convertFrom . insert . S.convertTo
  replaceUserImpl i v = liftDB $ replace (S.convertTo i) (S.convertTo v)
  deleteUserImpl = liftDB . delete . S.convertTo
  hasPerm i p = liftDB $ do
    c <- count [S.UserPermUser ==. S.convertTo i, S.UserPermPermission ==. p]
    return $ c > 0
  getFirstUserByPerm p = liftDB . fmap (fmap toWithId) $ do
    mp <- selectFirst [S.UserPermPermission ==. p] []
    case mp of
      Nothing -> return Nothing
      Just (Entity _ S.UserPerm{..}) -> fmap (Entity userPermUser) <$> get userPermUser
  selectUserImplGroups i = liftDB . fmap (fmap toWithId) $ selectList [S.AuthUserGroupUsersUser ==. S.convertTo i] [Asc S.AuthUserGroupUsersGroup]
  clearUserImplGroups i = liftDB $ deleteWhere [S.AuthUserGroupUsersUser ==. S.convertTo i]
  insertAuthUserGroup = liftDB . fmap S.convertFrom . insert . S.convertTo
  insertAuthUserGroupUsers = liftDB . fmap S.convertFrom . insert . S.convertTo
  insertAuthUserGroupPerms = liftDB . fmap S.convertFrom . insert . S.convertTo
  getAuthUserGroup = liftDB . fmap (fmap S.convertFrom) . get . S.convertTo
  listAuthUserGroupPermissions i = liftDB . fmap (fmap toWithId) $ selectList [S.AuthUserGroupPermsGroup ==. S.convertTo i] [Asc S.AuthUserGroupPermsPermission]
  listAuthUserGroupUsers i = liftDB . fmap (fmap toWithId) $ selectList [S.AuthUserGroupUsersGroup ==. S.convertTo i] [Asc S.AuthUserGroupUsersUser]
  replaceAuthUserGroup i v = liftDB $ replace (S.convertTo i) (S.convertTo v)
  clearAuthUserGroupUsers i = liftDB $ deleteWhere [S.AuthUserGroupUsersGroup ==. S.convertTo i]
  clearAuthUserGroupPerms i = liftDB $ deleteWhere [S.AuthUserGroupPermsGroup ==. S.convertTo i]
  deleteAuthUserGroup = liftDB . delete . S.convertTo
  listGroupsPaged page size = liftDB $ do
    groups <- selectList [] [Asc S.AuthUserGroupId, OffsetBy (fromIntegral $ page * size), LimitTo (fromIntegral size)]
    total <- count ([] :: [Filter S.AuthUserGroup])
    return (fmap toWithId groups, fromIntegral total)
  setAuthUserGroupName i n = liftDB $ update (S.convertTo i) [S.AuthUserGroupName =. n]
  setAuthUserGroupParent i mp = liftDB $ update (S.convertTo i) [S.AuthUserGroupParent =. fmap S.convertTo mp]
  insertSingleUseCode = liftDB . fmap S.convertFrom . insert . S.convertTo
  setSingleUseCodeUsed i mt = liftDB $ update (S.convertTo i) [S.UserSingleUseCodeUsed =. mt]
  getUnusedCode c i t = liftDB . fmap (fmap toWithId) $ selectFirst ([
          S.UserSingleUseCodeValue ==. c
        , S.UserSingleUseCodeUser ==. S.convertTo i
        , S.UserSingleUseCodeUsed ==. Nothing
        ] ++ (
            [S.UserSingleUseCodeExpire ==. Nothing]
        ||. [S.UserSingleUseCodeExpire >=. Just t]
    )) [Desc S.UserSingleUseCodeExpire]
  invalidatePermamentCodes i t = liftDB $ updateWhere [
      S.UserSingleUseCodeUser ==. S.convertTo i
    , S.UserSingleUseCodeUsed ==. Nothing
    , S.UserSingleUseCodeExpire ==. Nothing
    ]
    [S.UserSingleUseCodeUsed =. Just t]
  selectLastRestoreCode i t = liftDB . fmap (fmap toWithId) $ selectFirst [S.UserRestoreUser ==. S.convertTo i, S.UserRestoreExpire >. t] [Desc S.UserRestoreExpire]
  insertUserRestore = liftDB . fmap S.convertFrom . insert . S.convertTo
  findRestoreCode i rc t = liftDB . fmap (fmap toWithId) $ selectFirst [S.UserRestoreUser ==. S.convertTo i, S.UserRestoreValue ==. rc, S.UserRestoreExpire >. t] [Desc S.UserRestoreExpire]
  replaceRestoreCode i v = liftDB $ replace (S.convertTo i) (S.convertTo v)
  findAuthToken i t = liftDB . fmap (fmap toWithId) $ selectFirst [S.AuthTokenUser ==. S.convertTo i, S.AuthTokenExpire >. t] []
  findAuthTokenByValue t = liftDB . fmap (fmap toWithId) $ selectFirst [S.AuthTokenValue ==. t] []
  insertAuthToken = liftDB . fmap S.convertFrom . insert . S.convertTo
  replaceAuthToken i v = liftDB $ replace (S.convertTo i) (S.convertTo v)
