module API(
    ExampleAPI
  ) where

import Servant.API
import Servant.API.Auth.Token

-- Your application endpoints
type ExampleEndpoint = "test"
      :> TokenHeader' '["test-permission"]
      :> Get '[JSON] ()

type ExampleAPI =
       ExampleEndpoint
  -- This is required for actual testing
  :<|> AuthSigninPostMethod
  :<|> AuthTouchMethod
  :<|> AuthSignoutMethod
