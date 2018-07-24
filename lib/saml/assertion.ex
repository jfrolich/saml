defmodule SAML.Assertion do
  defstruct version: "2.0",
            issue_instant: "",
            recipient: "",
            issuer: "",
            subject: %SAML.Subject{},
            conditions: %{},
            attributes: %{}
end
