module Servant.Server.Auth.Token.Persistent(
    PersistentBackendT
  , runPersistentBackendT
  ) where

import Control.Monad.Reader
import Control.Monad.Trans.Control
import Data.Aeson.WithField
import Database.Persist
import Database.Persist.Sql
import Servant.Server.Auth.Token.Model

import qualified Servant.Server.Auth.Token.Persistent.Schema as S

-- | Monad transformer that implements storage backend
newtype PersistentBackendT m a = PersistentBackendT { unPersistentBackendT :: SqlPersistT m a }
  deriving (Functor, Applicative, Monad, MonadIO, MonadReader SqlBackend)

-- | Execute backend action with given connection pool.
runPersistentBackendT :: MonadBaseControl IO m => ConnectionPool -> PersistentBackendT m a -> m a
runPersistentBackendT pool ma = runSqlPool (unPersistentBackendT ma) pool

-- | Convert entity struct to 'WithId' version
toWithId :: (S.ConvertStorage a' a, S.ConvertStorage (Key a') i) => Entity a' -> WithId i a
toWithId (Entity k v) = WithField (S.convertFrom k) (S.convertFrom v)

instance (MonadIO m) => HasStorage (PersistentBackendT m) where
  getUserImpl = PersistentBackendT . fmap (fmap S.convertFrom) . get . S.convertTo
  getUserImplByLogin = PersistentBackendT . fmap (fmap toWithId) . getBy . S.UniqueLogin
  listUsersPaged page size = PersistentBackendT $ do
    users <- selectList [] [Asc S.UserImplId, OffsetBy (fromIntegral $ page * size), LimitTo (fromIntegral size)]
    total <- count ([] :: [Filter S.UserImpl])
    return (fmap toWithId users, fromIntegral total)
  getUserImplPermissions uid = PersistentBackendT . fmap (fmap toWithId) $ selectList [S.UserPermUser ==. S.convertTo uid] [Asc S.UserPermPermission]
  deleteUserPermissions uid = PersistentBackendT $ deleteWhere [S.UserPermUser ==. S.convertTo uid]
  insertUserPerm = PersistentBackendT . fmap S.convertFrom . insert . S.convertTo
  insertUserImpl = PersistentBackendT . fmap S.convertFrom . insert . S.convertTo
  replaceUserImpl i v = PersistentBackendT $ replace (S.convertTo i) (S.convertTo v)
  deleteUserImpl = PersistentBackendT . delete . S.convertTo
  hasPerm i p = PersistentBackendT $ do
    c <- count [S.UserPermUser ==. S.convertTo i, S.UserPermPermission ==. p]
    return $ c > 0
  getFirstUserByPerm p = PersistentBackendT . fmap (fmap toWithId) $ do
    mp <- selectFirst [S.UserPermPermission ==. p] []
    case mp of
      Nothing -> return Nothing
      Just (Entity _ S.UserPerm{..}) -> fmap (Entity userPermUser) <$> get userPermUser
  selectUserImplGroups i = PersistentBackendT . fmap (fmap toWithId) $ selectList [S.AuthUserGroupUsersUser ==. S.convertTo i] [Asc S.AuthUserGroupUsersGroup]
  clearUserImplGroups i = PersistentBackendT $ deleteWhere [S.AuthUserGroupUsersUser ==. S.convertTo i]
  insertAuthUserGroup = PersistentBackendT . fmap S.convertFrom . insert . S.convertTo
  insertAuthUserGroupUsers = PersistentBackendT . fmap S.convertFrom . insert . S.convertTo
  insertAuthUserGroupPerms = PersistentBackendT . fmap S.convertFrom . insert . S.convertTo
  getAuthUserGroup = PersistentBackendT . fmap (fmap S.convertFrom) . get . S.convertTo
  listAuthUserGroupPermissions i = PersistentBackendT . fmap (fmap toWithId) $ selectList [S.AuthUserGroupPermsGroup ==. S.convertTo i] [Asc S.AuthUserGroupPermsPermission]
  listAuthUserGroupUsers i = PersistentBackendT . fmap (fmap toWithId) $ selectList [S.AuthUserGroupUsersGroup ==. S.convertTo i] [Asc S.AuthUserGroupUsersUser]
  replaceAuthUserGroup i v = PersistentBackendT $ replace (S.convertTo i) (S.convertTo v)
  clearAuthUserGroupUsers i = PersistentBackendT $ deleteWhere [S.AuthUserGroupUsersGroup ==. S.convertTo i]
  clearAuthUserGroupPerms i = PersistentBackendT $ deleteWhere [S.AuthUserGroupPermsGroup ==. S.convertTo i]
  deleteAuthUserGroup = PersistentBackendT . delete . S.convertTo
  listGroupsPaged page size = PersistentBackendT $ do
    groups <- selectList [] [Asc S.AuthUserGroupId, OffsetBy (fromIntegral $ page * size), LimitTo (fromIntegral size)]
    total <- count ([] :: [Filter S.AuthUserGroup])
    return (fmap toWithId groups, fromIntegral total)
  setAuthUserGroupName i n = PersistentBackendT $ update (S.convertTo i) [S.AuthUserGroupName =. n]
  setAuthUserGroupParent i mp = PersistentBackendT $ update (S.convertTo i) [S.AuthUserGroupParent =. fmap S.convertTo mp]
  insertSingleUseCode = PersistentBackendT . fmap S.convertFrom . insert . S.convertTo
  setSingleUseCodeUsed i mt = PersistentBackendT $ update (S.convertTo i) [S.UserSingleUseCodeUsed =. mt]
  getUnusedCode c i t = PersistentBackendT . fmap (fmap toWithId) $ selectFirst ([
          S.UserSingleUseCodeValue ==. c
        , S.UserSingleUseCodeUser ==. S.convertTo i
        , S.UserSingleUseCodeUsed ==. Nothing
        ] ++ (
            [S.UserSingleUseCodeExpire ==. Nothing]
        ||. [S.UserSingleUseCodeExpire >=. Just t]
    )) [Desc S.UserSingleUseCodeExpire]
  invalidatePermamentCodes i t = PersistentBackendT $ updateWhere [
      S.UserSingleUseCodeUser ==. S.convertTo i
    , S.UserSingleUseCodeUsed ==. Nothing
    , S.UserSingleUseCodeExpire ==. Nothing
    ]
    [S.UserSingleUseCodeUsed =. Just t]
  selectLastRestoreCode i t = PersistentBackendT . fmap (fmap toWithId) $ selectFirst [S.UserRestoreUser ==. S.convertTo i, S.UserRestoreExpire >. t] [Desc S.UserRestoreExpire]
  insertUserRestore = PersistentBackendT . fmap S.convertFrom . insert . S.convertTo
  findRestoreCode i rc t = PersistentBackendT . fmap (fmap toWithId) $ selectFirst [S.UserRestoreUser ==. S.convertTo i, S.UserRestoreValue ==. rc, S.UserRestoreExpire >. t] [Desc S.UserRestoreExpire]
  replaceRestoreCode i v = PersistentBackendT $ replace (S.convertTo i) (S.convertTo v)
  findAuthToken i t = PersistentBackendT . fmap (fmap toWithId) $ selectFirst [S.AuthTokenUser ==. S.convertTo i, S.AuthTokenExpire >. t] []
  findAuthTokenByValue t = PersistentBackendT . fmap (fmap toWithId) $ selectFirst [S.AuthTokenValue ==. t] []
  insertAuthToken = PersistentBackendT . fmap S.convertFrom . insert . S.convertTo
  replaceAuthToken i v = PersistentBackendT $ replace (S.convertTo i) (S.convertTo v)
