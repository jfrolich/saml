defmodule SAML.AuthnRequest do
  defstruct version: "2.0",
            issue_instant: "",
            destination: "",
            issuer: "",
            consumer_location: ""

  import SAML.XMerl.Record

  def to_xml(%__MODULE__{
        version: v,
        issue_instant: time,
        destination: dest,
        issuer: issuer,
        consumer_location: consumer
      }) do
    ns =
      xml_namespace(
        nodes: [
          {'samlp', :"urn:oasis:names:tc:SAML:2.0:protocol"},
          {'saml', :"urn:oasis:names:tc:SAML:2.0:assertion"}
        ]
      )

    SAML.Utils.build_nsinfo(
      ns,
      xml_element(
        name: :"samlp:AuthnRequest",
        attributes: [
          xml_attribute(name: :"xmlns:samlp", value: :"urn:oasis:names:tc:SAML:2.0:protocol"),
          xml_attribute(name: :"xmlns:saml", value: :"urn:oasis:names:tc:SAML:2.0:assertion"),
          xml_attribute(name: :IssueInstant, value: to_charlist(time)),
          xml_attribute(name: :Version, value: to_charlist(v)),
          xml_attribute(name: :Destination, value: to_charlist(dest)),
          xml_attribute(name: :AssertionConsumerServiceURL, value: to_charlist(consumer)),
          xml_attribute(
            name: :ProtocolBinding,
            value: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
          )
        ],
        content: [
          xml_element(
            name: :"saml:Issuer",
            content: [
              xml_text(value: to_charlist(issuer))
            ]
          ),
          xml_element(
            name: :"saml:Subject",
            content: [
              xml_element(
                name: :"saml:SubjectConfirmation",
                attributes: [
                  xml_attribute(name: :Method, value: 'urn:oasis:names:tc:SAML:2.0:cm:bearer')
                ]
              )
            ]
          )
        ]
      )
    )
  end
end
