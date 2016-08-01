{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE TemplateHaskell            #-}
module Servant.Server.Auth.Token.Model where 

import Control.Monad 
import Control.Monad.IO.Class 
import Control.Monad.Reader 
import Crypto.PasswordStore
import Data.Maybe
import Data.Monoid
import Data.Text (Text)
import Data.Time
import Database.Persist.Postgresql
import Database.Persist.TH 
import GHC.Generics

import qualified Data.ByteString as BS 
import qualified Data.Foldable as F 
import qualified Data.List as L 
import qualified Data.Sequence as S 
import qualified Data.Text.Encoding as TE 

import Servant.API.Auth.Token
import Servant.Server.Auth.Token.Common 
import Servant.Server.Auth.Token.Config 
import Servant.Server.Auth.Token.Patch 

share [mkPersist sqlSettings
     , mkDeleteCascade sqlSettings
     , mkMigrate "migrateAll"] [persistLowerCase|
UserImpl
  login       Login
  password    Password     -- encrypted with salt
  email       Email
  UniqueLogin login
  deriving Generic Show

UserPerm 
  user        UserImplId 
  permission  Permission
  deriving Generic Show

AuthToken
  value       SimpleToken 
  user        UserImplId
  expire      UTCTime
  deriving Generic Show

UserRestore
  value       RestoreCode
  user        UserImplId 
  expire      UTCTime 
  deriving Generic Show 

AuthUserGroup
  name        Text 
  parent      AuthUserGroupId Maybe
  deriving Generic Show 

AuthUserGroupUsers
  group       AuthUserGroupId 
  user        UserImplId 
  deriving Generic Show 

AuthUserGroupPerms
  group       AuthUserGroupId 
  permission  Permission
  deriving Generic Show 
|]

-- | Execute database transaction
runDB :: (MonadReader AuthConfig m, MonadIO m) => SqlPersistT IO b -> m b
runDB query = do
  pool <- asks getPool
  liftIO $ runSqlPool query pool

passToByteString :: Password -> BS.ByteString
passToByteString = TE.encodeUtf8

byteStringToPass :: BS.ByteString -> Password
byteStringToPass = TE.decodeUtf8

-- | Helper to convert user to response
userToUserInfo :: Entity UserImpl -> [Permission] -> [UserGroupId] -> RespUserInfo 
userToUserInfo (Entity uid UserImpl{..}) perms groups = RespUserInfo {
      respUserId = fromIntegral $ fromSqlKey uid
    , respUserLogin = userImplLogin
    , respUserEmail = userImplEmail
    , respUserPermissions = perms 
    , respUserGroups = groups
  }

-- | Get user by id
readUserInfo :: UserId -> SqlPersistT IO (Maybe RespUserInfo)
readUserInfo uid' = do 
  let uid = toKey uid'
  muser <- get uid 
  case muser of 
    Nothing -> return Nothing 
    Just user -> do 
      perms <- getUserPermissions uid 
      groups <- getUserGroups uid 
      return . Just $ 
        userToUserInfo (Entity uid user) perms groups

-- | Return list of permissions for the given user (only permissions that are assigned to him directly)
getUserPermissions :: UserImplId -> SqlPersistT IO [Permission]
getUserPermissions uid = do 
  perms <- selectList [UserPermUser ==. uid] [Asc UserPermPermission]
  return $ userPermPermission . entityVal <$> perms

-- | Return list of permissions for the given user
setUserPermissions :: UserImplId -> [Permission] -> SqlPersistT IO ()
setUserPermissions uid perms = do 
  deleteWhere [UserPermUser ==. uid]
  forM_ perms $ void . insert . UserPerm uid

-- | Creation of new user
createUser :: Int -> Login -> Password -> Email -> [Permission] -> SqlPersistT IO UserImplId 
createUser strength login pass email perms = do
  pass' <- liftIO $ makePassword (passToByteString pass) strength
  i <- insert UserImpl {
      userImplLogin = login
    , userImplPassword = byteStringToPass pass'
    , userImplEmail = email 
    }
  forM_ perms $ void . insert . UserPerm i 
  return i

-- | Check whether the user has particular permission
hasPerm :: UserImplId -> Permission -> SqlPersistT IO Bool 
hasPerm i perm = do 
  c <- count [UserPermUser ==. i, UserPermPermission ==. perm]
  return $ c > 0

-- | Check whether the user has particular permissions
hasPerms :: UserImplId -> [Permission] -> SqlPersistT IO Bool 
hasPerms _ [] = return True
hasPerms i perms = do 
  perms' <- getUserAllPermissions i 
  return $ and $ (`elem` perms') <$> perms 

-- | Creates user with admin privileges
createAdmin :: Int -> Login -> Password -> Email -> SqlPersistT IO UserImplId
createAdmin strength login pass email = createUser strength login pass email [adminPerm]

-- | Ensures that DB has at leas one admin, if not, creates a new one
-- with specified info.
ensureAdmin :: Int -> Login -> Password -> Email -> SqlPersistT IO ()
ensureAdmin strength login pass email = do 
  madmin <- selectFirst [UserPermPermission ==. adminPerm] []
  whenNothing madmin $ void $ createAdmin strength login pass email 

patchUser :: Int -> PatchUser -> Entity UserImpl -> SqlPersistT IO (Entity UserImpl)
patchUser strength PatchUser{..} =  
        withPatch patchUserLogin (\l (Entity i u) -> pure $ Entity i u { userImplLogin = l })
    >=> withPatch patchUserPassword patchPassword
    >=> withPatch patchUserEmail (\e (Entity i u) -> pure $ Entity i u { userImplEmail = e })
    >=> withPatch patchUserPermissions patchPerms
    >=> withPatch patchUserGroups patchGroups
    where 
      patchPassword ps (Entity i u) = Entity <$> pure i <*> setUserPassword' strength ps u
      patchPerms ps (Entity i u) = do 
        setUserPermissions i ps
        return $ Entity i u
      patchGroups gs (Entity i u) = do 
        setUserGroups i gs
        return $ Entity i u

setUserPassword' :: MonadIO m => Int -> Password -> UserImpl -> m UserImpl
setUserPassword' strength pass user = do
  pass' <- liftIO $ makePassword (passToByteString pass) strength
  return $ user { userImplPassword = byteStringToPass pass' }

-- | Get all groups the user belongs to
getUserGroups :: UserImplId -> SqlPersistT IO [UserGroupId]
getUserGroups i = fmap (fromKey . authUserGroupUsersGroup . entityVal)
  <$> selectList [AuthUserGroupUsersUser ==. i] [Asc AuthUserGroupUsersGroup]

-- | Rewrite all user groups
setUserGroups :: UserImplId -> [UserGroupId] -> SqlPersistT IO ()
setUserGroups i gs = do 
  deleteWhere [AuthUserGroupUsersUser ==. i]
  gs' <- validateGroups gs 
  forM_ gs' $ \g -> void $ insert (AuthUserGroupUsers g i)

-- | Leave only existing groups
validateGroups :: [UserGroupId] -> SqlPersistT IO [AuthUserGroupId]
validateGroups is = do
  pairs <- mapM ((\i -> (i,) <$> get i) . toKey) is 
  return $ fmap fst . filter (isJust . snd) $ pairs

-- | Getting permission of a group and all it parent groups
getGroupPermissions :: UserGroupId -> SqlPersistT IO [Permission]
getGroupPermissions = go S.empty S.empty . toKey
  where 
  go !visited !perms !i = do 
    mg <- get i 
    case mg of 
      Nothing -> return $ F.toList perms 
      Just AuthUserGroup{..} -> do 
        curPerms <- fmap (authUserGroupPermsPermission . entityVal) <$> 
          selectList [AuthUserGroupPermsGroup ==. i] [Asc AuthUserGroupPermsPermission]
        let perms' = perms <> S.fromList curPerms
        case authUserGroupParent of 
          Nothing -> return $ F.toList perms'
          Just pid -> if isJust $ pid `S.elemIndexL` visited
            then fail $ "Recursive user group graph: " <> show (visited S.|> pid)
            else go (visited S.|> pid) perms' pid 

-- | Get user permissions that are assigned to him/her via groups only
getUserGroupPermissions :: UserImplId -> SqlPersistT IO [Permission]
getUserGroupPermissions i = do 
  groups <- getUserGroups i 
  perms <- mapM getGroupPermissions groups 
  return $ L.sort . L.nub . concat $ perms

-- | Get user permissions that are assigned to him/her either by direct
-- way or by his/her groups.
getUserAllPermissions :: UserImplId -> SqlPersistT IO [Permission]
getUserAllPermissions i = do 
  permsDr <- getUserPermissions i 
  permsGr <- getUserGroupPermissions i 
  return $ L.sort . L.nub $ permsDr <> permsGr 

-- | Collect full info about user group from RDBMS
readUserGroup :: UserGroupId -> SqlPersistT IO (Maybe UserGroup)
readUserGroup i = do 
  let i' = toKey $ i 
  mu <- get i' 
  case mu of 
    Nothing -> return Nothing 
    Just AuthUserGroup{..} -> do 
      users <- fmap (authUserGroupUsersUser . entityVal) <$> 
        selectList [AuthUserGroupUsersGroup ==. i'] [Asc AuthUserGroupUsersUser]
      perms <- fmap (authUserGroupPermsPermission . entityVal) <$> 
        selectList [AuthUserGroupPermsGroup ==. i'] [Asc AuthUserGroupPermsPermission]
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
insertUserGroup :: UserGroup -> SqlPersistT IO UserGroupId
insertUserGroup u = do 
  let (ag, users, perms) = toAuthUserGroup u
  i <- insert ag 
  forM_ (users i) $ void . insert
  forM_ (perms i) $ void . insert
  return $ fromKey $ i 

-- | Replace user group with new value
updateUserGroup :: UserGroupId -> UserGroup -> SqlPersistT IO ()
updateUserGroup i u = do 
  let i' = toKey $ i 
  let (ag, users, perms) = toAuthUserGroup u
  replace i' ag 
  deleteWhere [AuthUserGroupUsersGroup ==. i'] 
  deleteWhere [AuthUserGroupPermsGroup ==. i']
  forM_ (users i') $ void . insert
  forM_ (perms i') $ void . insert

-- | Erase user group from RDBMS, cascade
deleteUserGroup :: UserGroupId -> SqlPersistT IO ()
deleteUserGroup i = do 
  let i' = toKey $ i 
  deleteWhere [AuthUserGroupUsersGroup ==. i'] 
  deleteWhere [AuthUserGroupPermsGroup ==. i']
  deleteCascade i'

-- | Partial update of user group
patchUserGroup :: UserGroupId -> PatchUserGroup -> SqlPersistT IO ()
patchUserGroup i PatchUserGroup{..} = do 
  let i' = toKey $ i
      patchName = (\n -> AuthUserGroupName =. n) <$> patchUserGroupName
      patchParent = case patchUserGroupNoParent of 
        Just True -> Just $ AuthUserGroupParent =. Nothing 
        _ -> (\p -> AuthUserGroupParent =. Just (toSqlKey .fromIntegral $ p)) <$> patchUserGroupParent
  update i' $ catMaybes [patchName, patchParent]
  whenJust patchUserGroupUsers $ \uids -> do
    deleteWhere [AuthUserGroupUsersGroup ==. i'] 
    forM_ uids $ insert . AuthUserGroupUsers i' . toKey  
  whenJust patchUserGroupPermissions $ \perms -> do
    deleteWhere [AuthUserGroupUsersGroup ==. i'] 
    forM_ perms $ insert . AuthUserGroupPerms i'
