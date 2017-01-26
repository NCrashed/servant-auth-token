{-# OPTIONS_GHC -fno-warn-orphans #-}
{-|
Module      : Servant.Server.Auth.Token
Description : Implementation of token authorisation API
Copyright   : (c) Anton Gushcha, 2016
License     : MIT
Maintainer  : ncrashed@gmail.com
Stability   : experimental
Portability : Portable

The module is server side implementation of "Servant.API.Auth.Token" API and intended to be
used as drop in module for user servers or as external micro service.

To use the server as constituent part, you need to provide customised 'AuthConfig' for
'authServer' function and implement 'AuthMonad' instance for your handler monad.

@
import Servant.Server.Auth.Token as Auth

-- | Example of user side configuration
data Config = Config {
  -- | Authorisation specific configuration
  authConfig :: AuthConfig
  -- other fields
  -- ...
}

-- | Example of user side handler monad
newtype App a = App {
    runApp :: ReaderT Config (ExceptT ServantErr IO) a
  } deriving ( Functor, Applicative, Monad, MonadReader Config,
               MonadError ServantErr, MonadIO)

-- | Now you can use authorisation API in your handler
instance AuthMonad App where
  getAuthConfig = asks authConfig
  liftAuthAction = App . lift

-- | Include auth 'migrateAll' function into your migration code
doMigrations :: SqlPersistT IO ()
doMigrations = runMigrationUnsafe $ do
  migrateAll -- other user migrations
  Auth.migrateAll -- creation of authorisation entities
  -- optional creation of default admin if db is empty
  ensureAdmin 17 "admin" "123456" "admin@localhost"
@

Now you can use 'guardAuthToken' to check authorisation headers in endpoints of your server:

@
-- | Read a single customer from DB
customerGet :: CustomerId -- ^ Customer unique id
  -> MToken' '["customer-read"] -- ^ Required permissions for auth token
  -> App Customer -- ^ Customer data
customerGet i token = do
  guardAuthToken token
  guard404 "customer" $ getCustomer i
@

-}
module Servant.Server.Auth.Token(
  -- * Implementation
    authServer
  -- * Server API
  , HasStorage(..)
  , AuthMonad(..)
  -- * Helpers
  , guardAuthToken
  , ensureAdmin
  , authUserByToken
  -- * API methods
  , authSignin
  , authSigninGetCode
  , authSigninPostCode
  , authTouch
  , authToken
  , authSignout
  , authSignup
  , authUsersInfo
  , authUserInfo
  , authUserPatch
  , authUserPut
  , authUserDelete
  , authRestore
  , authGetSingleUseCodes
  , authGroupGet
  , authGroupPost
  , authGroupPut
  , authGroupPatch
  , authGroupDelete
  , authGroupList
  -- * Low-level API
  , getAuthToken
  ) where

import Control.Monad
import Control.Monad.Except
import Control.Monad.Reader
import Crypto.PasswordStore
import Data.Aeson.Unit
import Data.Aeson.WithField
import Data.Maybe
import Data.Monoid
import Data.Text.Encoding
import Data.Time.Clock
import Data.UUID
import Data.UUID.V4
import Servant

import Servant.API.Auth.Token
import Servant.API.Auth.Token.Pagination
import Servant.Server.Auth.Token.Common
import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.Model
import Servant.Server.Auth.Token.Monad
import Servant.Server.Auth.Token.Pagination
import Servant.Server.Auth.Token.Restore
import Servant.Server.Auth.Token.SingleUse

import qualified Data.ByteString.Lazy as BS

-- | This function converts our 'AuthHandler' monad into the @ExceptT ServantErr
-- IO@ monad that Servant's 'enter' function needs in order to run the
-- application. The ':~>' type is a natural transformation, or, in
-- non-category theory terms, a function that converts two type
-- constructors without looking at the values in the types.
convertAuthHandler :: AuthConfig db -> AuthHandler db :~> ExceptT ServantErr IO
convertAuthHandler cfg = Nat (flip runReaderT cfg . runAuthHandler)

-- | The interface your application should implement to be able to use
-- token authorisation API.
class (Monad m, HasStorage (AuthHandler db)) => AuthMonad db m | m -> db where
  getAuthConfig :: m (AuthConfig db)
  liftAuthAction :: ExceptT ServantErr IO a -> m a

instance HasStorage (AuthHandler db) => AuthMonad db (AuthHandler db) where
  getAuthConfig = getConfig
  liftAuthAction = AuthHandler . lift

-- | Helper to run handler in 'AuthMonad' context
runAuth :: AuthMonad db m => AuthHandler db a -> m a
runAuth m = do
  cfg <- getAuthConfig
  let Nat conv = convertAuthHandler cfg
  liftAuthAction $ conv m

-- | Implementation of AuthAPI
authServer :: HasStorage (AuthHandler db) => AuthConfig db -> Server AuthAPI
authServer cfg = enter (convertAuthHandler cfg) (
       authSignin
  :<|> authSigninGetCode
  :<|> authSigninPostCode
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
  :<|> authGetSingleUseCodes
  :<|> authGroupGet
  :<|> authGroupPost
  :<|> authGroupPut
  :<|> authGroupPatch
  :<|> authGroupDelete
  :<|> authGroupList)

-- | Implementation of "signin" method
authSignin :: AuthMonad db m
  => Maybe Login -- ^ Login query parameter
  -> Maybe Password -- ^ Password query parameter
  -> Maybe Seconds -- ^ Expire query parameter, how many seconds the token is valid
  -> m (OnlyField "token" SimpleToken) -- ^ If everything is OK, return token
authSignin mlogin mpass mexpire = runAuth $ do
  login <- require "login" mlogin
  pass <- require "pass" mpass
  WithField uid UserImpl{..} <- guardLogin login pass
  OnlyField <$> getAuthToken uid mexpire
  where
  guardLogin login pass = do -- check login and password, return passed user
    muser <- getUserImplByLogin login
    let err = throw401 "Cannot find user with given combination of login and pass"
    case muser of
      Nothing -> err
      Just user@(WithField _ UserImpl{..}) -> if passToByteString pass `verifyPassword` passToByteString userImplPassword
        then return user
        else err

-- | Helper to get or generate new token for user
getAuthToken :: AuthMonad db m
  => UserImplId -- ^ User for whom we want token
  -> Maybe Seconds -- ^ Expiration duration, 'Nothing' means default
  -> m SimpleToken -- ^ Old token (if it doesn't expire) or new one
getAuthToken uid mexpire = runAuth $ do
  expire <- calcExpire mexpire
  mt <- getExistingToken  -- check whether there is already existing token
  case mt of
    Nothing -> createToken expire -- create new token
    Just t -> touchToken t expire -- prolong token expiration time
  where
  getExistingToken = do -- return active token for specified user id
    t <- liftIO getCurrentTime
    findAuthToken uid t

  createToken expire = do -- generate and save fresh token
    token <- toText <$> liftIO nextRandom
    _ <- insertAuthToken AuthToken {
        authTokenValue = token
      , authTokenUser = uid
      , authTokenExpire = expire
      }
    return token

-- | Authorisation via code of single usage.
--
-- Implementation of 'AuthSigninGetCodeMethod' endpoint.
--
-- Logic of authorisation via this method is:
--
-- * Client sends GET request to 'AuthSigninGetCodeMethod' endpoint
--
-- * Server generates single use token and sends it via
--   SMS or email, defined in configuration by 'singleUseCodeSender' field.
--
-- * Client sends POST request to 'AuthSigninPostCodeMethod' endpoint
--
-- * Server responds with auth token.
--
-- * Client uses the token with other requests as authorisation
-- header
--
-- * Client can extend lifetime of token by periodically pinging
-- of 'AuthTouchMethod' endpoint
--
-- * Client can invalidate token instantly by 'AuthSignoutMethod'
--
-- * Client can get info about user with 'AuthTokenInfoMethod' endpoint.
--
-- See also: 'authSigninPostCode'
authSigninGetCode :: AuthMonad db m
  => Maybe Login -- ^ User login, required
  -> m Unit
authSigninGetCode mlogin = runAuth $ do
  login <- require "login" mlogin
  uinfo <- guard404 "user" $ readUserInfoByLogin login
  let uid = toKey $ respUserId uinfo

  AuthConfig{..} <- getConfig
  code <- liftIO singleUseCodeGenerator
  expire <- makeSingleUseExpire singleUseCodeExpire
  registerSingleUseCode uid code (Just expire)
  liftIO $ singleUseCodeSender uinfo code

  return Unit

-- | Authorisation via code of single usage.
--
-- Logic of authorisation via this method is:
--
-- * Client sends GET request to 'AuthSigninGetCodeMethod' endpoint
--
-- * Server generates single use token and sends it via
--   SMS or email, defined in configuration by 'singleUseCodeSender' field.
--
-- * Client sends POST request to 'AuthSigninPostCodeMethod' endpoint
--
-- * Server responds with auth token.
--
-- * Client uses the token with other requests as authorisation
-- header
--
-- * Client can extend lifetime of token by periodically pinging
-- of 'AuthTouchMethod' endpoint
--
-- * Client can invalidate token instantly by 'AuthSignoutMethod'
--
-- * Client can get info about user with 'AuthTokenInfoMethod' endpoint.
--
-- See also: 'authSigninGetCode'
authSigninPostCode :: AuthMonad db m
  => Maybe Login -- ^ User login, required
  -> Maybe SingleUseCode -- ^ Received single usage code, required
  -> Maybe Seconds
  -- ^ Time interval after which the token expires, 'Nothing' means
  -- some default value
  -> m (OnlyField "token" SimpleToken)
authSigninPostCode mlogin mcode mexpire = runAuth $ do
  login <- require "login" mlogin
  code <- require "code" mcode

  uinfo <- guard404 "user" $ readUserInfoByLogin login
  let uid = toKey $ respUserId uinfo
  isValid <- validateSingleUseCode uid code
  unless isValid $ throw401 "Single usage code doesn't match"

  OnlyField <$> getAuthToken uid mexpire

-- | Calculate expiration timestamp for token
calcExpire :: Maybe Seconds -> AuthHandler db UTCTime
calcExpire mexpire = do
  t <- liftIO getCurrentTime
  AuthConfig{..} <- getConfig
  let requestedExpire = maybe defaultExpire fromIntegral mexpire
  let boundedExpire = maybe requestedExpire (min requestedExpire) maximumExpire
  return $ boundedExpire `addUTCTime` t

-- prolong token with new timestamp
touchToken :: HasStorage (AuthHandler db) => WithId AuthTokenId AuthToken -> UTCTime -> AuthHandler db SimpleToken
touchToken (WithField tid tok) expire = do
  replaceAuthToken tid tok {
      authTokenExpire = expire
    }
  return $ authTokenValue tok

-- | Implementation of "touch" method
authTouch :: AuthMonad db m
  => Maybe Seconds -- ^ Expire query parameter, how many seconds the token should be valid by now. 'Nothing' means default value defined in server config.
  -> MToken '[] -- ^ Authorisation header with token
  -> m Unit
authTouch mexpire token = runAuth $ do
  WithField i mt <- guardAuthToken' (fmap unToken token) []
  expire <- calcExpire mexpire
  replaceAuthToken i mt { authTokenExpire = expire }
  return Unit

-- | Implementation of "token" method, return
-- info about user binded to the token
authToken :: AuthMonad db m
  => MToken '[] -- ^ Authorisation header with token
  -> m RespUserInfo
authToken token = runAuth $ do
  i <- authUserByToken token
  guard404 "user" . readUserInfo . fromKey $ i

-- | Getting user id by token
authUserByToken :: AuthMonad db m => MToken '[] -> m UserImplId
authUserByToken token = runAuth $ do
  WithField _ mt <- guardAuthToken' (fmap unToken token) []
  return $ authTokenUser mt

-- | Implementation of "signout" method
authSignout :: AuthMonad db m
  => Maybe (Token '[]) -- ^ Authorisation header with token
  -> m Unit
authSignout token = runAuth $ do
  WithField i mt <- guardAuthToken' (fmap unToken token) []
  expire <- liftIO getCurrentTime
  replaceAuthToken i mt { authTokenExpire = expire }
  return Unit

-- | Checks given password and if it is invalid in terms of config
-- password validator, throws 400 error.
guardPassword :: Password -> AuthHandler db ()
guardPassword p = do
  AuthConfig{..} <- getConfig
  whenJust (passwordValidator p) $ throw400 . BS.fromStrict . encodeUtf8

-- | Implementation of "signup" method
authSignup :: AuthMonad db m
  => ReqRegister -- ^ Registration info
  -> MToken' '["auth-register"] -- ^ Authorisation header with token
  -> m (OnlyField "user" UserId)
authSignup ReqRegister{..} token = runAuth $ do
  guardAuthToken token
  guardUserInfo
  guardPassword reqRegPassword
  strength <- getsConfig passwordsStrength
  i <- createUser strength reqRegLogin reqRegPassword reqRegEmail reqRegPermissions
  whenJust reqRegGroups $ setUserGroups i
  return $ OnlyField . fromKey $ i
  where
    guardUserInfo = do
      mu <- getUserImplByLogin reqRegLogin
      whenJust mu $ const $ throw400 "User with specified id is already registered"

-- | Implementation of get "users" method
authUsersInfo :: AuthMonad db m
  => Maybe Page -- ^ Page num parameter
  -> Maybe PageSize -- ^ Page size parameter
  -> MToken' '["auth-info"] -- ^ Authorisation header with token
  -> m RespUsersInfo
authUsersInfo mp msize token = runAuth $ do
  guardAuthToken token
  pagination mp msize $ \page size -> do
    (users', total) <- listUsersPaged page size
    perms <- mapM (getUserPermissions . (\(WithField i _) -> i)) users'
    groups <- mapM (getUserGroups . (\(WithField i _) -> i)) users'
    let users = zip3 users' perms groups
    return RespUsersInfo {
        respUsersItems = (\(user, ps, grs) -> userToUserInfo user ps grs) <$> users
      , respUsersPages = ceiling $ (fromIntegral total :: Double) / fromIntegral size
      }

-- | Implementation of get "user" method
authUserInfo :: AuthMonad db m
  => UserId -- ^ User id
  -> MToken' '["auth-info"] -- ^ Authorisation header with token
  -> m RespUserInfo
authUserInfo uid' token = runAuth $ do
  guardAuthToken token
  guard404 "user" $ readUserInfo uid'

-- | Implementation of patch "user" method
authUserPatch :: AuthMonad db m
  => UserId -- ^ User id
  -> PatchUser -- ^ JSON with fields for patching
  -> MToken' '["auth-update"] -- ^ Authorisation header with token
  -> m Unit
authUserPatch uid' body token = runAuth $ do
  guardAuthToken token
  whenJust (patchUserPassword body) guardPassword
  let uid = toKey uid'
  user <- guardUser uid
  strength <- getsConfig passwordsStrength
  WithField _ user' <- patchUser strength body $ WithField uid user
  replaceUserImpl uid user'
  return Unit

-- | Implementation of put "user" method
authUserPut :: AuthMonad db m
  => UserId -- ^ User id
  -> ReqRegister -- ^ New user
  -> MToken' '["auth-update"] -- ^ Authorisation header with token
  -> m Unit
authUserPut uid' ReqRegister{..} token = runAuth $ do
  guardAuthToken token
  guardPassword reqRegPassword
  let uid = toKey uid'
  let user = UserImpl {
        userImplLogin = reqRegLogin
      , userImplPassword = ""
      , userImplEmail = reqRegEmail
      }
  user' <- setUserPassword reqRegPassword user
  replaceUserImpl uid user'
  setUserPermissions uid reqRegPermissions
  whenJust reqRegGroups $ setUserGroups uid
  return Unit

-- | Implementation of patch "user" method
authUserDelete :: AuthMonad db m
  => UserId -- ^ User id
  -> MToken' '["auth-delete"] -- ^ Authorisation header with token
  -> m Unit
authUserDelete uid' token = runAuth $ do
  guardAuthToken token
  deleteUserImpl $ toKey uid'
  return Unit

-- Generate new password for user. There is two phases, first, the method
-- is called without 'code' parameter. The system sends email with a restore code
-- to email. After that a call of the method with the code is needed to
-- change password. Need configured SMTP server.
authRestore :: AuthMonad db m
  => UserId -- ^ User id
  -> Maybe RestoreCode
  -> Maybe Password
  -> m Unit
authRestore uid' mcode mpass = runAuth $ do
  let uid = toKey uid'
  user <- guardUser uid
  case mcode of
    Nothing -> do
      dt <- getsConfig restoreExpire
      t <- liftIO getCurrentTime
      AuthConfig{..} <- getConfig
      rc <- getRestoreCode restoreCodeGenerator uid $ addUTCTime dt t
      uinfo <- guard404 "user" $ readUserInfo uid'
      sendRestoreCode uinfo rc
    Just code -> do
      pass <- require "password" mpass
      guardPassword pass
      guardRestoreCode uid code
      user' <- setUserPassword pass user
      replaceUserImpl uid user'
  return Unit

-- | Implementation of 'AuthGetSingleUseCodes' endpoint.
authGetSingleUseCodes :: AuthMonad db m
  => UserId -- ^ Id of user
  -> Maybe Word -- ^ Number of codes. 'Nothing' means that server generates some default count of codes.
  -- And server can define maximum count of codes that user can have at once.
  -> MToken' '["auth-single-codes"]
  -> m (OnlyField "codes" [SingleUseCode])
authGetSingleUseCodes uid mcount token = runAuth $ do
  guardAuthToken token
  let uid' = toKey uid
  _ <- guard404 "user" $ readUserInfo uid
  AuthConfig{..} <- getConfig
  let n = min singleUseCodePermamentMaximum $ fromMaybe singleUseCodeDefaultCount mcount
  OnlyField <$> generateSingleUsedCodes uid' singleUseCodeGenerator n

-- | Getting user by id, throw 404 response if not found
guardUser :: HasStorage (AuthHandler db) => UserImplId -> AuthHandler db UserImpl
guardUser uid = do
  muser <- getUserImpl uid
  case muser of
    Nothing -> throw404 "User not found"
    Just user -> return user

-- | If the token is missing or the user of the token
-- doesn't have needed permissions, throw 401 response
guardAuthToken :: forall perms m db . (PermsList perms, AuthMonad db m) => MToken perms -> m ()
guardAuthToken mt = runAuth $ void $ guardAuthToken' (fmap unToken mt) $ unliftPerms (Proxy :: Proxy perms)

-- | Same as `guardAuthToken` but returns record about the token
guardAuthToken' :: HasStorage (AuthHandler db) => Maybe SimpleToken -> [Permission] -> AuthHandler db (WithId AuthTokenId AuthToken)
guardAuthToken' Nothing _ = throw401 "Token required"
guardAuthToken' (Just token) perms = do
  t <- liftIO getCurrentTime
  mt <- findAuthTokenByValue token
  case mt of
    Nothing -> throw401 "Token is not valid"
    Just et@(WithField _ AuthToken{..}) -> do
      when (t > authTokenExpire) $ throwError $ err401 { errBody = "Token expired" }
      mu <- getUserImpl authTokenUser
      case mu of
        Nothing -> throw500 "User of the token doesn't exist"
        Just UserImpl{..} -> do
          isAdmin <- hasPerm authTokenUser adminPerm
          hasAllPerms <- hasPerms authTokenUser perms
          unless (isAdmin || hasAllPerms) $ throw401 $
            "User doesn't have all required permissions: " <> showb perms
          return et

-- | Rehash password for user
setUserPassword :: Password -> UserImpl -> AuthHandler db UserImpl
setUserPassword pass user = do
  strength <- getsConfig passwordsStrength
  setUserPassword' strength pass user

-- | Getting info about user group, requires 'authInfoPerm' for token
authGroupGet :: AuthMonad db m
  => UserGroupId
  -> MToken' '["auth-info"] -- ^ Authorisation header with token
  -> m UserGroup
authGroupGet i token = runAuth $ do
  guardAuthToken token
  guard404 "user group" $ readUserGroup i

-- | Inserting new user group, requires 'authUpdatePerm' for token
authGroupPost :: AuthMonad db m
  => UserGroup
  -> MToken' '["auth-update"] -- ^ Authorisation header with token
  -> m (OnlyId UserGroupId)
authGroupPost ug token = runAuth $ do
  guardAuthToken token
  OnlyField <$> insertUserGroup ug

-- | Replace info about given user group, requires 'authUpdatePerm' for token
authGroupPut :: AuthMonad db m
  => UserGroupId
  -> UserGroup
  -> MToken' '["auth-update"] -- ^ Authorisation header with token
  -> m Unit
authGroupPut i ug token = runAuth $ do
  guardAuthToken token
  updateUserGroup i ug
  return Unit

-- | Patch info about given user group, requires 'authUpdatePerm' for token
authGroupPatch :: AuthMonad db m
  => UserGroupId
  -> PatchUserGroup
  -> MToken' '["auth-update"] -- ^ Authorisation header with token
  -> m Unit
authGroupPatch i up token = runAuth $ do
  guardAuthToken token
  patchUserGroup i up
  return Unit

-- | Delete all info about given user group, requires 'authDeletePerm' for token
authGroupDelete :: AuthMonad db m
  => UserGroupId
  -> MToken' '["auth-delete"] -- ^ Authorisation header with token
  -> m Unit
authGroupDelete i token = runAuth $ do
  guardAuthToken token
  deleteUserGroup i
  return Unit

-- | Get list of user groups, requires 'authInfoPerm' for token
authGroupList :: AuthMonad db m
  => Maybe Page
  -> Maybe PageSize
  -> MToken' '["auth-info"] -- ^ Authorisation header with token
  -> m (PagedList UserGroupId UserGroup)
authGroupList mp msize token = runAuth $ do
  guardAuthToken token
  pagination mp msize $ \page size -> do
    (groups', total) <- listGroupsPaged page size
    groups <- forM groups' $ (\i -> fmap (WithField i) <$> readUserGroup i) . fromKey . (\(WithField i _) -> i)
    return PagedList {
        pagedListItems = catMaybes groups
      , pagedListPages = ceiling $ (fromIntegral total :: Double) / fromIntegral size
      }
