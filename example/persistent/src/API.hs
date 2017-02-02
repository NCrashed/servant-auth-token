module API(
    ExampleAPI
  ) where

import Servant.API
import Servant.API.Auth.Token

type ExampleAPI = "test"
  :> TokenHeader' '["test-permission"]
  :> Get '[JSON] ()
