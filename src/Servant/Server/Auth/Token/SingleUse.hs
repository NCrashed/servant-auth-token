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
  , invalidateSingleUseCode
  , validateSingleUseCode
  , generateSingleUsedCodes
  ) where

import Control.Monad
import Control.Monad.IO.Class
import Data.Aeson.WithField
import Data.Time
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
registerSingleUseCode :: HasStorage m => UserImplId -- ^ Id of user
  -> SingleUseCode -- ^ Single usage code
  -> Maybe UTCTime -- ^ Time when the code expires, 'Nothing' is never expiring code
  -> m ()
registerSingleUseCode uid code expire = void $ insertSingleUseCode
  $ UserSingleUseCode code uid expire Nothing

-- | Marks single use code that it cannot be used again
invalidateSingleUseCode :: HasStorage m => UserSingleUseCodeId -- ^ Id of code
  -> m ()
invalidateSingleUseCode i = do
  t <- liftIO getCurrentTime
  setSingleUseCodeUsed i $ Just t

-- | Check single use code and return 'True' on success.
--
-- On success invalidates single use code.
validateSingleUseCode :: HasStorage m => UserImplId -- ^ Id of user
  -> SingleUseCode -- ^ Single usage code
  -> m Bool
validateSingleUseCode uid code = do
  t <- liftIO getCurrentTime
  mcode <- getUnusedCode code uid t
  whenJust mcode $ invalidateSingleUseCode . (\(WithField i _) -> i)
  return $ maybe False (const True) mcode

-- | Generates a set single use codes that doesn't expire.
--
-- Note: previous codes without expiration are invalidated.
generateSingleUsedCodes :: HasStorage m => UserImplId -- ^ Id of user
  -> IO SingleUseCode -- ^ Generator of codes
  -> Word -- Count of codes
  -> m [SingleUseCode]
generateSingleUsedCodes uid gen n = do
  t <- liftIO getCurrentTime
  invalidatePermanentCodes uid t
  replicateM (fromIntegral n) $ do
    code <- liftIO gen
    _ <- insertSingleUseCode $ UserSingleUseCode code uid Nothing Nothing
    return code
