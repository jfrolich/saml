defmodule SAMLTest do
  use ExUnit.Case
  doctest SAML

  def parse_xml!(str) do
    {doc, _} = :xmerl_scan.string(str |> to_charlist(), [{:namespace_conformant, true}])
    doc
  end

  @xml """
    <samlp:Response
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      Version="2.0"
      IssueInstant="2013-01-01T01:01:01Z" Destination="foo">
    </samlp:Response>
  """
  test "decode response" do
    doc = parse_xml!(@xml)

    assert {:ok,
            %SAML.Response{
              issue_instant: "2013-01-01T01:01:01Z",
              destination: "foo",
              status: :unknown
            }} = SAML.decode_response(doc)
  end

  @xml """
    <samlp:Response
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      IssueInstant="2013-01-01T01:01:01Z"
      Destination="foo">
    </samlp:Response>
  """
  test "no version" do
    doc = parse_xml!(@xml)

    assert {:error, :bad_version} == SAML.decode_response(doc)
  end

  @xml """
    <samlp:Response
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      Version="2.0"
      Destination="foo">
    </samlp:Response>
  """
  test "no issue instant" do
    doc = parse_xml!(@xml)

    assert {:error, :bad_response} == SAML.decode_response(doc)
  end

  @xml """
    <samlp:Response
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      Version="2.0"
      IssueInstant="2013-01-01T01:01:01Z">
    </samlp:Response>
  """
  test "destination is optional" do
    doc = parse_xml!(@xml)

    assert {:ok,
            %SAML.Response{
              issue_instant: "2013-01-01T01:01:01Z",
              status: :unknown
            }} = SAML.decode_response(doc)
  end

  @xml """
    <samlp:Response
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      Version="2.0"
      IssueInstant="2013-01-01T01:01:01Z"
    >
      <saml:Issuer>foo</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode
          Value="urn:oasis:names:tc:SAML:2.0:status:Success"
        />
      </samlp:Status>
    </samlp:Response>
  """
  test "response status" do
    doc = parse_xml!(@xml)

    assert {:ok,
            %SAML.Response{
              issue_instant: "2013-01-01T01:01:01Z",
              status: :success,
              issuer: "foo"
            }} = SAML.decode_response(doc)
  end

  @xml """
    <samlp:Response
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      Version="2.0"
      IssueInstant="2013-01-01T01:01:01Z">
        <saml:Issuer>foo</saml:Issuer>
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
        </samlp:Status>
        <saml:Assertion>
        </saml:Assertion>
    </samlp:Response>
  """
  test "bad assertion" do
    doc = parse_xml!(@xml)

    assert {:error, :bad_version} = SAML.decode_response(doc)
  end

  @xml """
    <samlp:Response
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      Version="2.0"
      IssueInstant="2013-01-01T01:01:01Z"
    >
      <saml:Issuer>foo</saml:Issuer>
      <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
      </samlp:Status>
      <saml:Assertion
        Version="2.0"
        IssueInstant="test">
          <saml:Issuer>foo</saml:Issuer>
          <saml:Subject>
            <saml:NameID>foobar</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer" />
          </saml:Subject>
      </saml:Assertion>
    </samlp:Response>
  """
  test "no recipient test" do
    doc = parse_xml!(@xml)

    assert {:error, :bad_recipient} = SAML.decode_response(doc)
  end

  @xml """
    <samlp:Response
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      Version="2.0"
      IssueInstant="2013-01-01T01:01:01Z">
        <saml:Issuer>foo</saml:Issuer>
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
        </samlp:Status>
        <saml:Assertion
          Version="2.0"
          IssueInstant="test">
            <saml:Issuer>foo</saml:Issuer>
            <saml:Subject>
              <saml:NameID>foobar</saml:NameID>
              <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData Recipient="foobar123" />
              </saml:SubjectConfirmation>
            </saml:Subject>
        </saml:Assertion>
      </samlp:Response>
  """
  test "decode assertion" do
    doc = parse_xml!(@xml)

    assert {:ok,
            %SAML.Response{
              issue_instant: "2013-01-01T01:01:01Z",
              issuer: "foo",
              status: :success,
              assertion: %SAML.Assertion{
                issue_instant: "test",
                issuer: "foo",
                recipient: "foobar123",
                subject: %SAML.Subject{
                  name: "foobar",
                  confirmation_method: :bearer
                }
              }
            }} = SAML.decode_response(doc)
  end

  @xml """
    <samlp:Response
      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      Version="2.0"
      IssueInstant="2013-01-01T01:01:01Z">
        <saml:Issuer>foo</saml:Issuer>
        <samlp:Status>
          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
        </samlp:Status>
        <saml:Assertion Version="2.0" IssueInstant="test">
          <saml:Issuer>foo</saml:Issuer>
          <saml:Subject>
            <saml:NameID>foobar</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
              <saml:SubjectConfirmationData Recipient="foobar123" />
            </saml:SubjectConfirmation>
          </saml:Subject>
          <saml:Conditions
            NotBefore="before"
            NotOnOrAfter="notafter">
            <saml:AudienceRestriction>
              <saml:Audience>foobaraudience</saml:Audience>
            </saml:AudienceRestriction>
          </saml:Conditions>
        </saml:Assertion>
    </samlp:Response>
  """
  test "decode conditions" do
    doc = parse_xml!(@xml)

    {:ok,
     %SAML.Response{
       assertion: %SAML.Assertion{
         conditions: conditions
       }
     }} = SAML.decode_response(doc)

    assert %{
             audience: "foobaraudience",
             not_before: "before",
             not_on_or_after: "notafter"
           } = conditions
  end

  @xml """
    <saml:Assertion
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      Version="2.0"
      IssueInstant="test">
        <saml:Subject>
          <saml:NameID>foobar</saml:NameID>
          <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData Recipient=\"foobar123\" />
          </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:AttributeStatement>
          <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3">
            <saml:AttributeValue>test@test.com</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="foo">
            <saml:AttributeValue>george</saml:AttributeValue>
            <saml:AttributeValue>bar</saml:AttributeValue>
          </saml:Attribute>
          <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
            <saml:AttributeValue>test@test.com</saml:AttributeValue>
          </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
  """
  test "decode attributes" do
    doc = parse_xml!(@xml)

    {:ok,
     %SAML.Assertion{
       attributes: %{
         "emailaddress" => "test@test.com",
         "foo" => ["george", "bar"],
         "mail" => "test@test.com"
       }
     }} = SAML.decode_assertion(doc)
  end
end
