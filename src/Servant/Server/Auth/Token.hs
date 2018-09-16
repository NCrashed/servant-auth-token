{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE UndecidableInstances #-}
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



Use 'guardAuthToken' to check authorisation headers in endpoints of your server:

@
-- | Read a single customer from DB
customerGet :: CustomerId -- ^ Customer unique id
  -> MToken' '["customer-read"] -- ^ Required permissions for auth token
  -> ServerM Customer -- ^ Customer data
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
  , AuthHandler
  -- * Helpers
  , guardAuthToken
  , guardAuthToken'
  , WithAuthToken(..)
  , ensureAdmin
  , authUserByToken
  -- * Combinators
  , AuthPerm
  , AuthAction(..)
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
  , authCheckPermissionsMethod
  , authGetUserIdMethod
  , authFindUserByLogin
  -- * Low-level API
  , getAuthToken
  , hashPassword
  , setUserPasswordHash
  , ensureAdminHash
  , signinByHashUnsafe
  ) where

import Control.Monad
import Control.Monad.Except
import Crypto.PasswordStore
import Data.Aeson.Unit
import Data.Aeson.WithField
import Data.Byteable (Byteable, toBytes, constEqBytes)
import Data.Maybe
import Data.Monoid
import Data.Text (Text)
import Data.Text.Encoding
import Data.Time.Clock
import Data.UUID
import Data.UUID.V4
import Servant

import Servant.API.Auth.Token
import Servant.API.Auth.Token.Pagination
import Servant.Server.Auth.Token.Common
import Servant.Server.Auth.Token.Combinator
import Servant.Server.Auth.Token.Config
import Servant.Server.Auth.Token.Model
import Servant.Server.Auth.Token.Monad
import Servant.Server.Auth.Token.Pagination
import Servant.Server.Auth.Token.Restore
import Servant.Server.Auth.Token.SingleUse

import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as BS

-- | Implementation of AuthAPI
authServer :: AuthHandler m => ServerT AuthAPI m
authServer =
       authSignin
  :<|> authSigninPost
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
  :<|> authGroupList
  :<|> authCheckPermissionsMethod
  :<|> authGetUserIdMethod
  :<|> authFindUserByLogin

-- | Implementation of "signin" method.
--
-- You can pass hashed password in format of `pwstore`. The library will
-- strengthen the hash and compare with hash in DB in this case. The feature
-- allow you to previously hash on client side to not pass the password as plain
-- text to server. Note that you should have the same salt in the passwords.
--
-- Also avoid having strength of hashed password less that is passed from client side.
--
-- Format of hashed password: "sha256|strength|salt|hash", where strength is an unsigned int, salt
-- is a base64-encoded 16-byte random number, and hash is a base64-encoded hash
-- value.
authSignin :: AuthHandler m
  => Maybe Login -- ^ Login query parameter
  -> Maybe Password -- ^ Password query parameter
  -> Maybe Seconds -- ^ Expire query parameter, how many seconds the token is valid
  -> m (OnlyField "token" SimpleToken) -- ^ If everything is OK, return token
authSignin mlogin mpass mexpire = do
  login <- require "login" mlogin
  pass <- require "pass" mpass
  WithField uid UserImpl{..} <- guardLogin login pass
  OnlyField <$> getAuthToken uid mexpire
  where
  checkPassword pass uimpl@UserImpl{..} = case readPwHash pass of
    Nothing -> pass `verifyPassword` passToByteString userImplPassword
    Just (passedStrength, passedSalt, passedHash) -> case readPwHash $ passToByteString userImplPassword of
      Nothing -> False
      Just (storedStrength, storedSalt, storedHash) -> if
        | not (passedSalt `constEqBytes` storedSalt) -> False
        | passedStrength == storedStrength -> passedHash `constEqBytes` storedHash
        | passedStrength < storedStrength -> let
            newPass = strengthenPassword pass storedStrength
            in checkPassword newPass uimpl
        | otherwise -> let
            newUserPass = strengthenPassword (passToByteString userImplPassword) passedStrength
            in checkPassword pass uimpl { userImplPassword = byteStringToPass newUserPass }
  guardLogin login pass = do -- check login and password, return passed user
    muser <- getUserImplByLogin login
    let err = throw401 "Cannot find user with given combination of login and pass"
    case muser of
      Nothing -> err
      Just user@(WithField _ uimpl) -> if checkPassword (passToByteString pass) uimpl
        then return user
        else err

-- | Implementation of "signin" method
authSigninPost :: AuthHandler m
  => AuthSigninPostBody -- ^ Holds login, password and token lifetime
  -> m (OnlyField "token" SimpleToken) -- ^ If everything is OK, return token
authSigninPost AuthSigninPostBody{..} = authSignin
  (Just authSigninBodyLogin)
  (Just authSigninBodyPassword)
  authSigninBodySeconds

-- | Helper to get or generate new token for user
getAuthToken :: AuthHandler m
  => UserImplId -- ^ User for whom we want token
  -> Maybe Seconds -- ^ Expiration duration, 'Nothing' means default
  -> m SimpleToken -- ^ Old token (if it doesn't expire) or new one
getAuthToken uid mexpire = do
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
authSigninGetCode :: AuthHandler m
  => Maybe Login -- ^ User login, required
  -> m Unit
authSigninGetCode mlogin = do
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
authSigninPostCode :: AuthHandler m
  => Maybe Login -- ^ User login, required
  -> Maybe SingleUseCode -- ^ Received single usage code, required
  -> Maybe Seconds
  -- ^ Time interval after which the token expires, 'Nothing' means
  -- some default value
  -> m (OnlyField "token" SimpleToken)
authSigninPostCode mlogin mcode mexpire = do
  login <- require "login" mlogin
  code <- require "code" mcode

  uinfo <- guard404 "user" $ readUserInfoByLogin login
  let uid = toKey $ respUserId uinfo
  isValid <- validateSingleUseCode uid code
  unless isValid $ throw401 "Single usage code doesn't match"

  OnlyField <$> getAuthToken uid mexpire

-- | Calculate expiration timestamp for token
calcExpire :: AuthHandler m => Maybe Seconds -> m UTCTime
calcExpire mexpire = do
  t <- liftIO getCurrentTime
  AuthConfig{..} <- getConfig
  let requestedExpire = maybe defaultExpire fromIntegral mexpire
  let boundedExpire = maybe requestedExpire (min requestedExpire) maximumExpire
  return $ boundedExpire `addUTCTime` t

-- prolong token with new timestamp
touchToken :: AuthHandler m => WithId AuthTokenId AuthToken -> UTCTime -> m SimpleToken
touchToken (WithField tid tok) expire = do
  replaceAuthToken tid tok {
      authTokenExpire = expire
    }
  return $ authTokenValue tok

-- | Implementation of "touch" method
authTouch :: AuthHandler m
  => Maybe Seconds -- ^ Expire query parameter, how many seconds the token should be valid by now. 'Nothing' means default value defined in server config.
  -> MToken '[] -- ^ Authorisation header with token
  -> m Unit
authTouch mexpire token = do
  WithField i mt <- guardAuthToken' (fmap unToken token) []
  expire <- calcExpire mexpire
  replaceAuthToken i mt { authTokenExpire = expire }
  return Unit

-- | Implementation of "token" method, return
-- info about user binded to the token
authToken :: AuthHandler m
  => MToken '[] -- ^ Authorisation header with token
  -> m RespUserInfo
authToken token = do
  i <- authUserByToken token
  guard404 "user" . readUserInfo . fromKey $ i

-- | Getting user id by token
authUserByToken :: AuthHandler m => MToken '[] -> m UserImplId
authUserByToken token = do
  WithField _ mt <- guardAuthToken' (fmap unToken token) []
  return $ authTokenUser mt

-- | Implementation of "signout" method
authSignout :: AuthHandler m
  => Maybe (Token '[]) -- ^ Authorisation header with token
  -> m Unit
authSignout token = do
  WithField i mt <- guardAuthToken' (fmap unToken token) []
  expire <- liftIO getCurrentTime
  replaceAuthToken i mt { authTokenExpire = expire }
  return Unit

-- | Checks given password and if it is invalid in terms of config
-- password validator, throws 400 error.
guardPassword :: AuthHandler m => Password -> m ()
guardPassword p = do
  AuthConfig{..} <- getConfig
  whenJust (passwordValidator p) $ throw400 . BS.fromStrict . encodeUtf8

-- | Implementation of "signup" method
authSignup :: AuthHandler m
  => ReqRegister -- ^ Registration info
  -> MToken' '["auth-register"] -- ^ Authorisation header with token
  -> m (OnlyField "user" UserId)
authSignup ReqRegister{..} token = do
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
authUsersInfo :: AuthHandler m
  => Maybe Page -- ^ Page num parameter
  -> Maybe PageSize -- ^ Page size parameter
  -> MToken' '["auth-info"] -- ^ Authorisation header with token
  -> m RespUsersInfo
authUsersInfo mp msize token = do
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
authUserInfo :: AuthHandler m
  => UserId -- ^ User id
  -> MToken' '["auth-info"] -- ^ Authorisation header with token
  -> m RespUserInfo
authUserInfo uid' token = do
  guardAuthToken token
  guard404 "user" $ readUserInfo uid'

-- | Implementation of patch "user" method
authUserPatch :: AuthHandler m
  => UserId -- ^ User id
  -> PatchUser -- ^ JSON with fields for patching
  -> MToken' '["auth-update"] -- ^ Authorisation header with token
  -> m Unit
authUserPatch uid' body token = do
  guardAuthToken token
  whenJust (patchUserPassword body) guardPassword
  let uid = toKey uid'
  user <- guardUser uid
  strength <- getsConfig passwordsStrength
  WithField _ user' <- patchUser strength body $ WithField uid user
  replaceUserImpl uid user'
  return Unit

-- | Implementation of put "user" method
authUserPut :: AuthHandler m
  => UserId -- ^ User id
  -> ReqRegister -- ^ New user
  -> MToken' '["auth-update"] -- ^ Authorisation header with token
  -> m Unit
authUserPut uid' ReqRegister{..} token = do
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
authUserDelete :: AuthHandler m
  => UserId -- ^ User id
  -> MToken' '["auth-delete"] -- ^ Authorisation header with token
  -> m Unit
authUserDelete uid' token = do
  guardAuthToken token
  deleteUserImpl $ toKey uid'
  return Unit

-- Generate new password for user. There is two phases, first, the method
-- is called without 'code' parameter. The system sends email with a restore code
-- to email. After that a call of the method with the code is needed to
-- change password. Need configured SMTP server.
authRestore :: AuthHandler m
  => UserId -- ^ User id
  -> Maybe RestoreCode
  -> Maybe Password
  -> m Unit
authRestore uid' mcode mpass = do
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
authGetSingleUseCodes :: AuthHandler m
  => UserId -- ^ Id of user
  -> Maybe Word -- ^ Number of codes. 'Nothing' means that server generates some default count of codes.
  -- And server can define maximum count of codes that user can have at once.
  -> MToken' '["auth-single-codes"]
  -> m (OnlyField "codes" [SingleUseCode])
authGetSingleUseCodes uid mcount token = do
  guardAuthToken token
  let uid' = toKey uid
  _ <- guard404 "user" $ readUserInfo uid
  AuthConfig{..} <- getConfig
  let n = min singleUseCodePermanentMaximum $ fromMaybe singleUseCodeDefaultCount mcount
  OnlyField <$> generateSingleUsedCodes uid' singleUseCodeGenerator n

-- | Getting user by id, throw 404 response if not found
guardUser :: AuthHandler m => UserImplId -> m UserImpl
guardUser uid = do
  muser <- getUserImpl uid
  case muser of
    Nothing -> throw404 "User not found"
    Just user -> return user

-- | If the token is missing or the user of the token
-- doesn't have needed permissions, throw 401 response
guardAuthToken :: forall perms m . (PermsList perms, AuthHandler m) => MToken perms -> m ()
guardAuthToken mt = void $ guardAuthToken' (fmap unToken mt) $ unliftPerms (Proxy :: Proxy perms)

class WithAuthToken a where

  -- | Authenticate an entire API rather than each individual
  -- endpoint.
  --
  -- As such, for a given 'HasServer' instance @api@, if you have:
  --
  -- @
  --   f :: 'ServerT' api m
  -- @
  --
  -- then:
  --
  -- @
  --   withAuthToken f :: (AuthHandler m) => ServerT ('TokenHeader' perms :> api) m
  -- @
  --
  -- (Note that the types don't reflect this, as it isn't possible to
  -- guarantee what all possible @ServerT@ instances might be.)
  withAuthToken :: (PermsList perms) => a -> MToken perms -> a

instance (AuthHandler m) => WithAuthToken (m a) where
  withAuthToken m mt = guardAuthToken mt *> m

instance {-# OVERLAPPING #-} (WithAuthToken r) => WithAuthToken (a -> r) where
  withAuthToken f mt = (`withAuthToken` mt) . f

instance (WithAuthToken a, WithAuthToken b) => WithAuthToken (a :<|> b) where
  withAuthToken (a :<|> b) mt = withAuthToken a mt :<|> withAuthToken b mt

-- | Same as `guardAuthToken` but returns record about the token
guardAuthToken' :: AuthHandler m => Maybe SimpleToken -> [Permission] -> m (WithId AuthTokenId AuthToken)
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
setUserPassword :: AuthHandler m => Password -> UserImpl -> m UserImpl
setUserPassword pass user = do
  strength <- getsConfig passwordsStrength
  setUserPassword' strength pass user

-- | Update password hash of user. Can be used to set direct hash for user password
-- when it is taken from config file.
setUserPasswordHash :: AuthHandler m => Text -> UserId -> m ()
setUserPasswordHash hashedPassword i = do
  let i' = toKey i
  user <- guard404 "user" $ getUserImpl i'
  let user' = user { userImplPassword = hashedPassword }
  replaceUserImpl i' user'

-- | Getting info about user group, requires 'authInfoPerm' for token
authGroupGet :: AuthHandler m
  => UserGroupId
  -> MToken' '["auth-info"] -- ^ Authorisation header with token
  -> m UserGroup
authGroupGet i token = do
  guardAuthToken token
  guard404 "user group" $ readUserGroup i

-- | Inserting new user group, requires 'authUpdatePerm' for token
authGroupPost :: AuthHandler m
  => UserGroup
  -> MToken' '["auth-update"] -- ^ Authorisation header with token
  -> m (OnlyId UserGroupId)
authGroupPost ug token = do
  guardAuthToken token
  OnlyField <$> insertUserGroup ug

-- | Replace info about given user group, requires 'authUpdatePerm' for token
authGroupPut :: AuthHandler m
  => UserGroupId
  -> UserGroup
  -> MToken' '["auth-update"] -- ^ Authorisation header with token
  -> m Unit
authGroupPut i ug token = do
  guardAuthToken token
  updateUserGroup i ug
  return Unit

-- | Patch info about given user group, requires 'authUpdatePerm' for token
authGroupPatch :: AuthHandler m
  => UserGroupId
  -> PatchUserGroup
  -> MToken' '["auth-update"] -- ^ Authorisation header with token
  -> m Unit
authGroupPatch i up token = do
  guardAuthToken token
  patchUserGroup i up
  return Unit

-- | Delete all info about given user group, requires 'authDeletePerm' for token
authGroupDelete :: AuthHandler m
  => UserGroupId
  -> MToken' '["auth-delete"] -- ^ Authorisation header with token
  -> m Unit
authGroupDelete i token = do
  guardAuthToken token
  deleteUserGroup i
  return Unit

-- | Get list of user groups, requires 'authInfoPerm' for token
authGroupList :: AuthHandler m
  => Maybe Page
  -> Maybe PageSize
  -> MToken' '["auth-info"] -- ^ Authorisation header with token
  -> m (PagedList UserGroupId UserGroup)
authGroupList mp msize token = do
  guardAuthToken token
  pagination mp msize $ \page size -> do
    (groups', total) <- listGroupsPaged page size
    groups <- forM groups' $ (\i -> fmap (WithField i) <$> readUserGroup i) . fromKey . (\(WithField i _) -> i)
    return PagedList {
        pagedListItems = catMaybes groups
      , pagedListPages = ceiling $ (fromIntegral total :: Double) / fromIntegral size
      }

-- | Check that the token has required permissions and return 'False' if it doesn't.
authCheckPermissionsMethod :: AuthHandler m
  => MToken' '["auth-check"] -- ^ Authorisation header with token
  -> OnlyField "permissions" [Permission] -- ^ Body with permissions to check
  -> m Bool -- ^ 'True' if all permissions are OK, 'False' if some permissions are not set for token and 401 error if the token doesn't have 'auth-check' permission.
authCheckPermissionsMethod token (OnlyField perms) = do
  guardAuthToken token
  let check = const True <$> guardAuthToken' (unToken <$> token) perms
  check `catchError` (\e -> if errHTTPCode e == 401 then pure True else throwError e)

-- | Get user ID for the owner of the speified token.
authGetUserIdMethod :: AuthHandler m
  => MToken' '["auth-userid"] -- ^ Authorisation header with token
  -> m (OnlyId UserId)
authGetUserIdMethod token = do
  guardAuthToken token
  OnlyField . respUserId <$> authToken (downgradeToken token)

-- | Implementation of 'AuthFindUserByLogin'. Find user by login, throw 404 error
-- if cannot find user by such login.
authFindUserByLogin :: AuthHandler m
  => Maybe Login -- ^ Login, 'Nothing' will cause 400 error.
  -> MToken' '["auth-info"]
  -> m RespUserInfo
authFindUserByLogin mlogin token = do
  login <- require "login" mlogin
  guardAuthToken token
  userWithId <- guard404 "user" $ getUserImplByLogin login
  makeUserInfo userWithId

-- | Generate hash from given password and return it as text. May be useful if
-- you don't like storing unencrypt passwords in config files.
hashPassword :: AuthHandler m => Password -> m Text
hashPassword pass = do
  strength <- getsConfig passwordsStrength
  hashed <- liftIO $ makePassword (passToByteString pass) strength
  return $ byteStringToPass hashed

-- | Ensures that DB has at least one admin, if not, creates a new one
-- with specified info and direct password hash. May be useful if
-- you don't like storing unencrypt passwords in config files.
ensureAdminHash :: AuthHandler m => Int -> Login -> Text -> Email -> m ()
ensureAdminHash strength login passHash email = do
  madmin <- getFirstUserByPerm adminPerm
  whenNothing madmin $ do
    i <- createAdmin strength login "" email
    setUserPasswordHash passHash $ fromKey i

-- | If you use password hash in configs, you cannot use them in signin
-- method. This helper allows to get token by password hash and the function
-- is not available for remote call (no endpoint).
--
-- Throws 401 if cannot find user or authorisation is failed.
--
-- WARNING: Do not expose the function to end user, never!
signinByHashUnsafe :: AuthHandler m => Login -- ^ User login
  -> Text -- ^ Hash of admin password
  -> Maybe Seconds -- ^ Expire
  -> m SimpleToken
signinByHashUnsafe login pass mexpire = do
  WithField uid UserImpl{..} <- guardLogin login pass
  getAuthToken uid mexpire
  where
  guardLogin login pass = do -- check login and password, return passed user
    muser <- getUserImplByLogin login
    let err = throw401 "Cannot find user with given combination of login and pass"
    case muser of
      Nothing -> err
      Just user@(WithField _ UserImpl{..}) -> if pass == userImplPassword
        then return user
        else err
