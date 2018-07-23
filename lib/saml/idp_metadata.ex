defmodule SAML.IDPMetadata do
  defstruct org: %SAML.Organization{},
            tech: %SAML.Contact{},
            signed_request: true,
            certificate: nil,
            entity_id: "",
            login_location: "",
            logout_location: nil,
            name_format: :unknown
end
