defmodule SAML.Response do
  defstruct version: "2.0",
            issue_instant: "",
            destination: "",
            issuer: "",
            status: :unknown,
            assertion: %SAML.Assertion{}
end
