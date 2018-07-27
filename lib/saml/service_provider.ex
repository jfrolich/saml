defmodule SAML.ServiceProvider do
  import SAML.XMerl.Record

  defstruct org: %SAML.Organization{},
            tech: %SAML.Contact{},
            key: nil,
            certificate: nil,
            cert_chain: [],
            sp_sign_requests: false,
            idp_signs_assertions: true,
            idp_signs_envelopes: true,
            idp_signs_logout_requests: true,
            sp_sign_metadata: false,
            trusted_fingerprints: [],
            metadata_uri: "",
            consume_uri: "",
            logout_uri: nil

  defp add_xml_id(xml) do
    xml_element(attributes: attributes) = xml

    xml_element(
      xml,
      attributes:
        attributes ++
          [
            xml_attribute(name: :ID, value: to_charlist(UUID.uuid1())),
            namespace: xml_namespace()
          ]
    )
  end

  @doc """
  return an authnrequest as an xml element
  """
  def generate_authn_request(
        idp_url,
        sp = %SAML.ServiceProvider{metadata_uri: metadata_uri, consume_uri: consume_uri}
      ) do
    now = :erlang.localtime_to_universaltime(:erlang.localtime())
    stamp = SAML.Utils.datetime_to_saml(now)

    xml =
      SAML.AuthnRequest.to_xml(%SAML.AuthnRequest{
        issue_instant: stamp,
        destination: idp_url,
        issuer: metadata_uri,
        consumer_location: consume_uri
      })

    if sp.sp_sign_requests do
      SAML.XMerl.Signature.sign(xml, sp.key, sp.certificate)
    else
      add_xml_id(xml)
    end
  end
end
