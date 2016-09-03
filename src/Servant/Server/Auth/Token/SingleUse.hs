{-|
Module      : Servant.Server.Auth.Token.SingleUse
Description : Specific functions to work with single usage codes.
Copyright   : (c) Anton Gushcha, 2016
License     : MIT
Maintainer  : ncrashed@gmail.com
Stability   : experimental
Portability : Portable
-}
module Servant.Server.Auth.Token.SingleUse(
    makeSingleUseExpire
  , registerSingleUseCode
  , invalideSingleUseCode
  , validateSingleUseCode
  , generateSingleUsedCodes
  ) where 

import Control.Monad
import Control.Monad.IO.Class 
import Data.Time 
import Database.Persist.Sql 
import Servant.API.Auth.Token
import Servant.Server.Auth.Token.Common
import Servant.Server.Auth.Token.Model 

-- | Calculate expire date for single usage code
makeSingleUseExpire :: MonadIO m => NominalDiffTime -- ^ Duration of code
  -> m UTCTime -- ^ Time when the code expires
makeSingleUseExpire dt = do 
  t <- liftIO getCurrentTime
  return $ dt `addUTCTime` t

-- | Register single use code in DB
registerSingleUseCode :: MonadIO m => UserImplId -- ^ Id of user
  -> SingleUseCode -- ^ Single usage code
  -> Maybe UTCTime -- ^ Time when the code expires, 'Nothing' is never expiring code
  -> SqlPersistT m () 
registerSingleUseCode uid code expire = void $ insert 
  $ UserSingleUseCode code uid expire Nothing

-- | Marks single use code that it cannot be used again
invalideSingleUseCode :: MonadIO m => UserSingleUseCodeId -- ^ Id of code
  -> SqlPersistT m ()
invalideSingleUseCode i = do
  t <- liftIO getCurrentTime
  update i [UserSingleUseCodeUsed =. Just t] 

-- | Check single use code and return 'True' on success.
--
-- On success invalidates single use code.
validateSingleUseCode :: MonadIO m => UserImplId -- ^ Id of user 
  -> SingleUseCode -- ^ Single usage code 
  -> SqlPersistT m Bool
validateSingleUseCode uid code = do 
  t <- liftIO getCurrentTime
  mcode <- selectFirst ([
      UserSingleUseCodeValue ==. code
    , UserSingleUseCodeUser ==. uid
    , UserSingleUseCodeUsed ==. Nothing
    ] ++ (
        [UserSingleUseCodeExpire ==. Nothing]
    ||. [UserSingleUseCodeExpire >=. Just t]
    )) [Desc UserSingleUseCodeExpire]
  whenJust mcode $ invalideSingleUseCode . entityKey
  return $ maybe False (const True) mcode

-- | Generates a set single use codes that doesn't expire.
--
-- Note: previous codes without expiration are invalidated.
generateSingleUsedCodes :: MonadIO m => UserImplId -- ^ Id of user
  -> IO SingleUseCode -- ^ Generator of codes
  -> Word -- Count of codes
  -> SqlPersistT m [SingleUseCode]
generateSingleUsedCodes uid gen n = do 
  t <- liftIO getCurrentTime
  updateWhere [
      UserSingleUseCodeUser ==. uid
    , UserSingleUseCodeUsed ==. Nothing
    , UserSingleUseCodeExpire ==. Nothing 
    ] 
    [UserSingleUseCodeUsed =. Just t]
  replicateM (fromIntegral n) $ do 
    code <- liftIO gen 
    _ <- insert $ UserSingleUseCode code uid Nothing Nothing
    return code
