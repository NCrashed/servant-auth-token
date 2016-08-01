{-# OPTIONS_GHC -fno-warn-orphans #-}
module Servant.Server.Auth.Token(
  -- * Implementation
    authServer
  -- * Server API
  , migrateAll
  , AuthMonad(..)
  -- * Helpers
  , guardAuthToken 
  , ensureAdmin
  , authUserByToken
  , downgradeToken
  ) where 

import Control.Monad 
import Control.Monad.Except 
import Control.Monad.Reader
import Crypto.PasswordStore
import Data.Aeson.WithField
import Data.Maybe
import Data.Monoid
import Data.Time.Clock
import Data.UUID
import Data.UUID.V4
import Database.Persist.Postgresql
import Servant 

import Servant.API.Auth.Token
import Servant.Server.Auth.Token.Common
import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.Model
import Servant.Server.Auth.Token.Monad
import Servant.Server.Auth.Token.Pagination
import Servant.Server.Auth.Token.Restore

-- | This function converts our 'AuthHandler' monad into the @ExceptT ServantErr
-- IO@ monad that Servant's 'enter' function needs in order to run the
-- application. The ':~>' type is a natural transformation, or, in
-- non-category theory terms, a function that converts two type
-- constructors without looking at the values in the types.
convertAuthHandler :: AuthConfig -> AuthHandler :~> ExceptT ServantErr IO
convertAuthHandler cfg = Nat (flip runReaderT cfg . runAuthHandler)

-- | The interface your application should implement to be able to use
-- token aurhorisation API.
class Monad m => AuthMonad m where 
  getAuthConfig :: m AuthConfig 
  liftAuthAction :: ExceptT ServantErr IO a -> m a 

instance AuthMonad AuthHandler where 
  getAuthConfig = getConfig 
  liftAuthAction = AuthHandler . lift 
  
-- | Helper to run handler in 'AuthMonad' context
runAuth :: AuthMonad m => AuthHandler a -> m a
runAuth m = do 
  cfg <- getAuthConfig
  let Nat conv = convertAuthHandler cfg 
  liftAuthAction $ conv m 

-- | Implementation of AuthAPI
authServer :: AuthConfig -> Server AuthAPI
authServer cfg = enter (convertAuthHandler cfg) (
       authSignin
  :<|> authTouch
  :<|> authToken 
  :<|> authSignout
  :<|> authSignup
  :<|> authUsersInfo
  :<|> authUserInfo
  :<|> authUserPatch
  :<|> authUserPut
  :<|> authUserDelete
  :<|> authRestore
  :<|> authGroupGet 
  :<|> authGroupPost
  :<|> authGroupPut 
  :<|> authGroupPatch
  :<|> authGroupDelete
  :<|> authGroupList)

-- | Implementation of "signin" method
authSignin :: Maybe Login -- ^ Login query parameter
  -> Maybe Password -- ^ Password query parameter
  -> Maybe Seconds -- ^ Expire query parameter, how many seconds the token is valid
  -> AuthHandler (OnlyField "token" SimpleToken) -- ^ If everthing is OK, return token
authSignin mlogin mpass mexpire = do
  login <- require "login" mlogin 
  pass <- require "pass" mpass 
  Entity uid UserImpl{..} <- guardLogin login pass
  expire <- calcExpire mexpire
  mt <- getExistingToken uid  -- check whether there is already existing token
  OnlyField <$> case mt of 
    Nothing -> createToken uid expire -- create new token
    Just t -> touchToken t expire -- prolong token expiration time
  where 
  guardLogin login pass = do -- check login and password, return passed user
    muser <- runDB $ selectFirst [UserImplLogin ==. login] []
    let err = throw401 "Cannot find user with given combination of login and pass"
    case muser of 
      Nothing -> err
      Just user@(Entity _ UserImpl{..}) -> if passToByteString pass `verifyPassword` passToByteString userImplPassword 
        then return user
        else err

  getExistingToken uid = do -- return active token for specified user id
    t <- liftIO getCurrentTime 
    runDB $ selectFirst [AuthTokenUser ==. uid, AuthTokenExpire >. t] []

  createToken uid expire = do -- generate and save fresh token 
    token <- toText <$> liftIO nextRandom
    _ <- runDB $ insert AuthToken {
        authTokenValue = token 
      , authTokenUser = uid 
      , authTokenExpire = expire 
      }
    return token 

-- | Calculate expiration timestamp for token
calcExpire :: Maybe Seconds -> AuthHandler UTCTime
calcExpire mexpire = do 
  t <- liftIO getCurrentTime
  dt <- getsConfig defaultExpire
  return $ maybe dt fromIntegral mexpire `addUTCTime` t

-- prolong token with new timestamp
touchToken :: Entity AuthToken -> UTCTime -> AuthHandler SimpleToken
touchToken (Entity tid tok) expire = do
  runDB $ replace tid tok {
      authTokenExpire = expire 
    }
  return $ authTokenValue tok

-- | Implementation of "touch" method
authTouch :: Maybe Seconds -- ^ Expire query parameter, how many seconds the token should be valid by now. 'Nothing' means default value defined in server config.
  -> MToken '[] -- ^ Authorisation header with token 
  -> AuthHandler ()
authTouch mexpire token = do 
  Entity i mt <- guardAuthToken' (fmap unToken token) []
  expire <- calcExpire mexpire
  runDB $ replace i mt { authTokenExpire = expire }

-- | Implementation of "token" method, return 
-- info about user binded to the token
authToken :: MToken '[] -- ^ Authorisation header with token 
  -> AuthHandler RespUserInfo 
authToken token = do 
  i <- authUserByToken token
  runDB404 "user" . readUserInfo . fromKey $ i

-- | Getting user id by token
authUserByToken :: AuthMonad m => MToken '[] -> m UserImplId 
authUserByToken token = runAuth $ do 
  Entity _ mt <- guardAuthToken' (fmap unToken token) []
  return $ authTokenUser mt 

-- | Implementation of "signout" method
authSignout :: Maybe (Token '[]) -- ^ Authorisation header with token 
  -> AuthHandler ()
authSignout token = do 
  Entity i mt <- guardAuthToken' (fmap unToken token) []
  expire <- liftIO getCurrentTime
  runDB $ replace i mt { authTokenExpire = expire }

-- | Implementation of "signup" method
authSignup :: ReqRegister -- ^ Registration info
  -> MToken '["auth-register"] -- ^ Authorisation header with token 
  -> AuthHandler (OnlyField "user" UserId)
authSignup ReqRegister{..} token = do 
  guardAuthToken token
  guardUserInfo
  strength <- getsConfig passwordsStrength
  i <- runDB $ do
    i <- createUser strength reqRegLogin reqRegPassword reqRegEmail reqRegPermissions
    whenJust reqRegGroups $ setUserGroups i
    return i
  return $ OnlyField . fromKey $ i 
  where 
    guardUserInfo = do 
      c <- runDB $ count [UserImplLogin ==. reqRegLogin]
      when (c > 0) $ throw400 "User with specified id is already registered"

-- | Implementation of get "users" method
authUsersInfo :: Maybe Page -- ^ Page num parameter
  -> Maybe PageSize -- ^ Page size parameter
  -> MToken '["auth-info"] -- ^ Authorisation header with token
  -> AuthHandler RespUsersInfo
authUsersInfo mp msize token = do 
  guardAuthToken token
  pagination mp msize $ \page size -> do 
    (users, total) <- runDB $ (,)
      <$> (do
        users <- selectList [] [Asc UserImplId, OffsetBy (fromIntegral $ page * size), LimitTo (fromIntegral size)]
        perms <- mapM (getUserPermissions . entityKey) users 
        groups <- mapM (getUserGroups . entityKey) users
        return $ zip3 users perms groups)
      <*> count ([] :: [Filter UserImpl])
    return RespUsersInfo {
        respUsersItems = (\(user, perms, groups) -> userToUserInfo user perms groups) <$> users 
      , respUsersPages = ceiling $ (fromIntegral total :: Double) / fromIntegral size
      }

-- | Implementation of get "user" method
authUserInfo :: UserId -- ^ User id 
  -> MToken '["auth-info"] -- ^ Authorisation header with token
  -> AuthHandler RespUserInfo
authUserInfo uid' token = do 
  guardAuthToken token
  runDB404 "user" $ readUserInfo uid'

-- | Implementation of patch "user" method
authUserPatch :: UserId -- ^ User id 
  -> PatchUser -- ^ JSON with fields for patching
  -> MToken '["auth-update"] -- ^ Authorisation header with token
  -> AuthHandler ()
authUserPatch uid' body token = do 
  guardAuthToken token
  let uid = toSqlKey . fromIntegral $ uid'
  user <- guardUser uid 
  strength <- getsConfig passwordsStrength
  Entity _ user' <- runDB $ patchUser strength body $ Entity uid user 
  runDB $ replace uid user'

-- | Implementation of put "user" method
authUserPut :: UserId -- ^ User id 
  -> ReqRegister -- ^ New user
  -> MToken '["auth-update"] -- ^ Authorisation header with token
  -> AuthHandler ()
authUserPut uid' ReqRegister{..} token = do 
  guardAuthToken token
  let uid = toSqlKey . fromIntegral $ uid'
  let user = UserImpl {
        userImplLogin = reqRegLogin
      , userImplPassword = ""
      , userImplEmail = reqRegEmail
      }
  user' <- setUserPassword reqRegPassword user 
  runDB $ do
    replace uid user'
    setUserPermissions uid reqRegPermissions
    whenJust reqRegGroups $ setUserGroups uid

-- | Implementation of patch "user" method
authUserDelete :: UserId -- ^ User id 
  -> MToken '["auth-delete"] -- ^ Authorisation header with token
  -> AuthHandler ()
authUserDelete uid' token = do 
  guardAuthToken token
  runDB $ deleteCascade (toKey uid' :: UserImplId)

-- Generate new password for user. There is two phases, first, the method
-- is called without 'code' parameter. The system sends email with a restore code
-- to email. After that a call of the method with the code is needed to 
-- change password. Need configured SMTP server.
authRestore :: UserId -- ^ User id 
  -> Maybe RestoreCode
  -> Maybe Password
  -> AuthHandler ()
authRestore uid' mcode mpass = do 
  let uid = toKey uid'
  user <- guardUser uid 
  case mcode of 
    Nothing -> do 
      dt <- getsConfig restoreExpire
      t <- liftIO getCurrentTime
      rc <- runDB $ getRestoreCode uid $ addUTCTime dt t 
      sendRestoreCode user rc 
    Just code -> do 
      guardRestoreCode uid code 
      pass <- require "password" mpass
      user' <- setUserPassword pass user
      runDB $ replace uid user'

-- | Getting user by id, throw 404 response if not found
guardUser :: UserImplId -> AuthHandler UserImpl
guardUser uid = do 
  muser <- runDB $ get uid 
  case muser of 
    Nothing -> throw404 "User not found"
    Just user -> return user 

-- | If the token is missing or the user of the token
-- doesn't have needed permissions, throw 401 response
guardAuthToken :: forall perms m . (PermsList perms, AuthMonad m) => MToken perms -> m ()
guardAuthToken mt = runAuth $ void $ guardAuthToken' (fmap unToken mt) $ unliftPerms (Proxy :: Proxy perms)

-- | Same as `guardAuthToken` but returns record about the token
guardAuthToken' :: Maybe SimpleToken -> [Permission] -> AuthHandler (Entity AuthToken)
guardAuthToken' Nothing _ = throw401 "Token required"
guardAuthToken' (Just token) perms = do 
  t <- liftIO getCurrentTime
  mt <- runDB $ selectFirst [AuthTokenValue ==. token] []
  case mt of 
    Nothing -> throw401 "Token is not valid"
    Just et@(Entity _ AuthToken{..}) -> do 
      when (t > authTokenExpire) $ throwError $ err401 { errBody = "Token expired" }
      mu <- runDB $ get authTokenUser
      case mu of 
        Nothing -> throw500 "User of the token doesn't exist"
        Just UserImpl{..} -> do
          isAdmin <- runDB $ hasPerm authTokenUser adminPerm
          hasAllPerms <- runDB $ hasPerms authTokenUser perms 
          unless (isAdmin || hasAllPerms) $ throw401 $
            "User doesn't have all required permissions: " <> showb perms
          return et

-- | Rehash password for user
setUserPassword :: Password -> UserImpl -> AuthHandler UserImpl
setUserPassword pass user = do 
  strength <- getsConfig passwordsStrength 
  setUserPassword' strength pass user 

-- | Getting info about user group, requires 'authInfoPerm' for token
authGroupGet :: UserGroupId
  -> MToken '["auth-info"] -- ^ Authorisation header with token
  -> AuthHandler UserGroup
authGroupGet i token = do 
  guardAuthToken token
  runDB404 "user group" $ readUserGroup i 

-- | Inserting new user group, requires 'authUpdatePerm' for token
authGroupPost :: UserGroup
  -> MToken '["auth-update"] -- ^ Authorisation header with token
  -> AuthHandler (OnlyId UserGroupId)
authGroupPost ug token = do 
  guardAuthToken token
  runDB $ OnlyField <$> insertUserGroup ug

-- | Replace info about given user group, requires 'authUpdatePerm' for token
authGroupPut :: UserGroupId
  -> UserGroup
  -> MToken '["auth-update"] -- ^ Authorisation header with token
  -> AuthHandler ()
authGroupPut i ug token = do 
  guardAuthToken token
  runDB $ updateUserGroup i ug 

-- | Patch info about given user group, requires 'authUpdatePerm' for token
authGroupPatch :: UserGroupId
  -> PatchUserGroup
  -> MToken '["auth-update"] -- ^ Authorisation header with token
  -> AuthHandler ()
authGroupPatch i up token = do 
  guardAuthToken token
  runDB $ patchUserGroup i up 

-- | Delete all info about given user group, requires 'authDeletePerm' for token
authGroupDelete :: UserGroupId
  -> MToken '["auth-delete"] -- ^ Authorisation header with token
  -> AuthHandler ()
authGroupDelete i token = do 
  guardAuthToken token
  runDB $ deleteUserGroup i 

-- | Get list of user groups, requires 'authInfoPerm' for token 
authGroupList :: Maybe Page
  -> Maybe PageSize
  -> MToken '["auth-info"] -- ^ Authorisation header with token
  -> AuthHandler (PagedList UserGroupId UserGroup)
authGroupList mp msize token = do 
  guardAuthToken token
  pagination mp msize $ \page size -> do 
    (groups, total) <- runDB $ (,)
      <$> (do
        is <- selectKeysList [] [Asc AuthUserGroupId, OffsetBy (fromIntegral $ page * size), LimitTo (fromIntegral size)]
        forM is $ (\i -> fmap (WithField i) <$> readUserGroup i) . fromKey)
      <*> count ([] :: [Filter AuthUserGroup])
    return PagedList {
        pagedListItems = catMaybes groups
      , pagedListPages = ceiling $ (fromIntegral total :: Double) / fromIntegral size
      }