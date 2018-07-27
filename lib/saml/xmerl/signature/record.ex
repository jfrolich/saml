defmodule SAML.XMerl.Signature.Record do
  require Record
  import Record, only: [defrecord: 3, extract: 2]

  defrecord :rsa_private_key,
            :RSAPrivateKey,
            extract(:RSAPrivateKey, from_lib: "public_key/include/public_key.hrl")
end
