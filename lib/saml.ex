defmodule SAML do
  @moduledoc """
  Documentation for Saml.
  """
  require __MODULE__.XPath
  alias __MODULE__.XPath

  import __MODULE__.XMerl.Record

  def init(_args) do
  end

  def nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"), do: :email
  def nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"), do: :x509

  def nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"),
    do: :windows

  def nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"), do: :krb
  def nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"), do: :persistent
  def nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"), do: :transient

  def subject_method_map("urn:oasis:names:tc:SAML:2.0:cm:bearer"), do: :bearer
  def subject_method_map(_), do: :unknown

  @status_prefix "urn:oasis:names:tc:SAML:2.0:status"
  defp status_code_map("#{@status_prefix}:Success"), do: :success
  defp status_code_map("#{@status_prefix}:VersionMismatch"), do: :bad_version
  defp status_code_map("#{@status_prefix}:AuthnFailed"), do: :authn_failed
  defp status_code_map("#{@status_prefix}:InvalidAttrNameOrValue"), do: :bad_attr
  defp status_code_map("#{@status_prefix}:RequestDenied"), do: :denied
  defp status_code_map("#{@status_prefix}:UnsupportedBinding"), do: :bad_binding
  defp status_code_map(_), do: :unknown

  defp common_attr_map("urn:oid:2.16.840.1.113730.3.1.3"), do: "employeeNumber"
  defp common_attr_map("urn:oid:1.3.6.1.4.1.5923.1.1.1.6"), do: "eduPersonPrincipalName"
  defp common_attr_map("urn:oid:0.9.2342.19200300.100.1.3"), do: "mail"
  defp common_attr_map("urn:oid:2.5.4.42"), do: "givenName"
  defp common_attr_map("urn:oid:2.16.840.1.113730.3.1.241"), do: "displayName"
  defp common_attr_map("urn:oid:2.5.4.3"), do: "commonName"
  defp common_attr_map("urn:oid:2.5.4.20"), do: "telephoneNumber"
  defp common_attr_map("urn:oid:2.5.4.10"), do: "organizationName"
  defp common_attr_map("urn:oid:2.5.4.11"), do: "organizationalUnitName"
  defp common_attr_map("urn:oid:1.3.6.1.4.1.5923.1.1.1.9"), do: "eduPersonScopedAffiliation"
  defp common_attr_map("urn:oid:2.16.840.1.113730.3.1.4"), do: "employeeType"
  defp common_attr_map("urn:oid:0.9.2342.19200300.100.1.1"), do: "uid"
  defp common_attr_map("urn:oid:2.5.4.4"), do: "surName"
  defp common_attr_map(uri = "http://" <> _), do: uri |> String.split("/") |> List.last()
  defp common_attr_map(other) when is_binary(other), do: other

  # hmm this creates an atom from random input
  # defp status_code_map(urn = "urn:" <> _),
  #   do: urn |> String.split(":") |> List.last() |> String.to_atom()

  @ns [
    {'samlp', :"urn:oasis:names:tc:SAML:2.0:protocol"},
    {'saml', :"urn:oasis:names:tc:SAML:2.0:assertion"},
    {'md', :"urn:oasis:names:tc:SAML:2.0:metadata"},
    {'ds', :"http://www.w3.org/2000/09/xmldsig#"}
  ]

  @entity_id_query '/md:EntityDescriptor/@entityID'
  @login_location_query '/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding=\'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\']/@Location'
  @logout_location_query '/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding=\'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\']/@Location'
  @name_format_query '/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat/text()'
  @certificate_query '/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use=\'signing\']/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()'
  @tech_query '/md:EntityDescriptor/md:ContactPerson[@contactType=\'technical\']'
  @org_query '/md:EntityDescriptor/md:Organization'

  defp decode_idp_metadata(xml) do
    with {:ok, entity_id} <- XPath.attr_required(xml, @ns, @entity_id_query, :bad_entity),
         {:ok, login_location} <-
           XPath.attr_required(xml, @ns, @login_location_query, :missing_sso_location),
         logout_location <- XPath.attr(xml, @ns, @logout_location_query, nil),
         name_format <- XPath.text(xml, @ns, @name_format_query, ""),
         {:ok, certificate} <-
           XPath.text_required(xml, @ns, @certificate_query, :missing_certificate),
         tech <- XPath.recurse(xml, @ns, @tech_query, nil),
         org <- XPath.recurse(xml, @ns, @org_query, nil) do
      {:ok,
       %SAML.IDPMetadata{
         entity_id: entity_id,
         login_location: login_location,
         logout_location: logout_location,
         name_format: nameid_map(name_format),
         certificate: certificate |> :erlang.list_to_binary() |> :base64.decode(),
         tech: decode_contact(tech),
         org: decode_org(org)
       }}
    end
  end

  @ns [
    {'samlp', :"urn:oasis:names:tc:SAML:2.0:protocol"},
    {'saml', :"urn:oasis:names:tc:SAML:2.0:assertion"},
    {'md', :"urn:oasis:names:tc:SAML:2.0:metadata"}
  ]

  @org_name_query '/md:Organization/md:OrganizationName/text()'
  @org_displayname_query '/md:Organization/md:OrganizationDisplayName/text()'
  @org_url_query '/md:Organization/md:OrganizationURL/text()'
  defp decode_org(xml) do
    with {:ok, name} <- XPath.text_required(xml, @ns, @org_name_query, :bad_org_name),
         displayname <- XPath.text(xml, @ns, @org_displayname_query, ""),
         url <- XPath.text(xml, @ns, @org_url_query, "") do
      {:ok,
       %SAML.Organization{
         name: name,
         displayname: displayname,
         url: url
       }}
    end
  end

  @contact_email_query '/md:ContactPerson/md:EmailAddress/text()'
  @contact_given_name_query '/md:ContactPerson/md:GivenName/text()'
  @contact_surname_query '/md:ContactPerson/md:SurName/text()'
  defp decode_contact(xml) do
    with {:ok, email} <- XPath.text_required(xml, @ns, @contact_email_query, :bad_contact_email),
         given_name <- XPath.text(xml, @ns, @contact_given_name_query, ""),
         surname <- XPath.text(xml, @ns, @contact_surname_query, "") do
      {:ok,
       %SAML.Contact{
         email: email,
         name: "#{given_name} #{surname}"
       }}
    end
  end

  @ns [
    {'saml', :"urn:oasis:names:tc:SAML:2.0:assertion"}
  ]

  @subject_name_query '/saml:Subject/saml:NameID/text()'
  @subject_confirmation_method_query '/saml:Subject/saml:SubjectConfirmation/@Method'
  @subject_notonorafter_query '/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter'
  defp decode_assertion_subject(xml) do
    with name <- XPath.text(xml, @ns, @subject_name_query, ""),
         confirmation_method <- XPath.attr(xml, @ns, @subject_confirmation_method_query, nil),
         notonorafter <- XPath.attr(xml, @ns, @subject_notonorafter_query, "") do
      %SAML.Subject{
        name: name,
        confirmation_method: subject_method_map(confirmation_method),
        notonorafter: notonorafter
      }
    end
  end

  @cond_not_before_query '/saml:Conditions/@NotBefore'
  @cond_not_on_or_after_query '/saml:Conditions/@NotOnOrAfter'
  @cond_audience_query '/saml:Conditions/saml:AudienceRestriction/saml:Audience/text()'
  defp decode_assertion_conditions(nil), do: %{}

  defp decode_assertion_conditions(xml) do
    with not_before <- XPath.attr(xml, @ns, @cond_not_before_query, nil),
         not_on_or_after <- XPath.attr(xml, @ns, @cond_not_on_or_after_query, nil),
         audience <- XPath.text(xml, @ns, @cond_audience_query, nil) do
      [
        not_before: not_before,
        not_on_or_after: not_on_or_after,
        audience: audience
      ]
      |> Enum.filter(&elem(&1, 1))
      |> Enum.into(%{})
    end
  end

  @attr_query '/saml:AttributeStatement/saml:Attribute'
  defp decode_assertion_attributes(nil), do: []

  defp decode_assertion_attributes(xml) do
    attrs = XPath.list(xml, @ns, @attr_query)

    Enum.reduce(attrs, %{}, fn attr, acc ->
      case Enum.find(xml_element(attr, :attributes), &(xml_attribute(&1, :name) === :Name)) do
        nil ->
          acc

        xml_attribute(value: name) ->
          name = to_string(name)

          case XPath.list(attr, @ns, 'saml:AttributeValue/text()') do
            [xml_text(value: value)] ->
              put_in(acc[common_attr_map(name)], to_string(value))

            list when length(list) > 0 ->
              value =
                list
                |> Enum.filter(&(elem(&1, 0) == :xmlText))
                |> Enum.map(&to_string(xml_text(&1, :value)))

              put_in(acc[common_attr_map(name)], value)

            _ ->
              acc
          end
      end
    end)
  end

  @ns [
    {'samlp', :"urn:oasis:names:tc:SAML:2.0:protocol"},
    {'saml', :"urn:oasis:names:tc:SAML:2.0:assertion"}
  ]

  @ass_version_query '/saml:Assertion/@Version'
  @ass_issue_instant_query '/saml:Assertion/@IssueInstant'
  @ass_recipient_query '/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient'
  @ass_issuer_query '/saml:Assertion/saml:Issuer/text()'
  @ass_subject_query '/saml:Assertion/saml:Subject'
  @ass_conditions_query '/saml:Assertion/saml:Conditions'
  @ass_attributes_query '/saml:Assertion/saml:AttributeStatement'

  def decode_assertion(nil), do: {:ok, %SAML.Assertion{}}

  def decode_assertion(xml) do
    # IO.inspect("decoding assertion")
    # IO.inspect(xml)

    with {:ok, version} <- XPath.attr_required(xml, @ns, @ass_version_query, :bad_version),
         {:ok, issue_instant} <-
           XPath.attr_required(xml, @ns, @ass_issue_instant_query, :bad_assertion),
         {:ok, recipient} <- XPath.attr_required(xml, @ns, @ass_recipient_query, :bad_recipient),
         issuer <- XPath.text(xml, @ns, @ass_issuer_query, ""),
         subject <- XPath.recurse(xml, @ns, @ass_subject_query, nil),
         conditions <- XPath.recurse(xml, @ns, @ass_conditions_query, nil),
         attributes <- XPath.recurse(xml, @ns, @ass_attributes_query, nil) do
      {:ok,
       %SAML.Assertion{
         version: version,
         issue_instant: issue_instant,
         recipient: recipient,
         issuer: issuer,
         subject: decode_assertion_subject(subject),
         conditions: decode_assertion_conditions(conditions),
         attributes: decode_assertion_attributes(attributes)
       }}
    end
  end

  defp validate_assertion_version(%SAML.Assertion{version: "2.0"}), do: :ok
  defp validate_assertion_version(_), do: {:error, :bad_version}

  defp validate_assertion_recipient(%SAML.Assertion{recipient: recipient}, recipient), do: :ok

  defp validate_assertion_recipient(_, _), do: {:error, :bad_recipient}

  defp validate_assertion_audience(
         %SAML.Assertion{conditions: %{audience: audience}},
         audience
       ),
       do: :ok

  defp validate_assertion_audience(%SAML.Assertion{conditions: %{audience: _}}, _),
    do: {:error, :bad_audience}

  defp validate_assertion_audience(_, _), do: :ok

  defp get_stale_time_from_subject(%SAML.Subject{notonorafter: ""}), do: nil

  defp get_stale_time_from_subject(%SAML.Subject{notonorafter: restrict}) do
    restrict
    |> SAML.Utils.saml_to_datetime()
    |> :calendar.datetime_to_gregorian_seconds()
  end

  defp get_stale_time_from_conditions(%{not_on_or_after: restrict}) do
    restrict |> SAML.Utils.saml_to_datetime() |> :calendar.datetime_to_gregorian_seconds()
  end

  defp get_stale_time_from_conditions(_), do: nil

  defp get_stale_time_from_issue_instant(issue_instant) do
    {:ok,
     issue_instant
     |> SAML.Utils.saml_to_datetime()
     |> :calendar.datetime_to_gregorian_seconds()
     |> Kernel.+(5 * 60)}
  end

  def stale_time(assertion) do
    Enum.min([
      get_stale_time_from_subject(assertion.subject),
      get_stale_time_from_conditions(assertion.conditions)
    ]) || get_stale_time_from_issue_instant(assertion.issue_instant)
  end

  defp now_in_seconds() do
    :erlang.localtime()
    |> :erlang.localtime_to_universaltime()
    |> :calendar.datetime_to_gregorian_seconds()
  end

  defp validate_assertion_stale(assertion) do
    if now_in_seconds() > stale_time(assertion) do
      {:error, :stale_assertion}
    else
      :ok
    end
  end

  @spec validate_assertion(
          assertion_xml :: SAML.XMerl.Record.xml_element(),
          recipient :: String.t(),
          audience :: String.t()
        ) :: {:ok, %SAML.Assertion{}} | {:error, reason :: atom}
  def validate_assertion(assertion_xml, recipient, audience) do
    with {:ok, assertion} <- decode_assertion(assertion_xml),
         :ok <- validate_assertion_version(assertion),
         :ok <- validate_assertion_recipient(assertion, recipient),
         :ok <- validate_assertion_audience(assertion, audience),
         :ok <- validate_assertion_stale(assertion) do
      {:ok, assertion}
    end
  end

  @response_version_query '/samlp:Response/@Version'
  @response_issue_instant_query '/samlp:Response/@IssueInstant'
  @response_destination_query '/samlp:Response/@Destination'
  @response_issuer_query '/samlp:Response/saml:Issuer/text()'
  @response_status_query '/samlp:Response/samlp:Status/samlp:StatusCode/@Value'
  @response_assertion_query '/samlp:Response/saml:Assertion'
  def decode_response(xml) do
    with {:ok, version} <- XPath.attr_required(xml, @ns, @response_version_query, :bad_version),
         {:ok, issue_instant} <-
           XPath.attr_required(xml, @ns, @response_issue_instant_query, :bad_response),
         destination <- XPath.attr(xml, @ns, @response_destination_query, ""),
         issuer <- XPath.text(xml, @ns, @response_issuer_query, ""),
         status <- XPath.attr(xml, @ns, @response_status_query, nil),
         assertion_raw <- XPath.recurse(xml, @ns, @response_assertion_query, nil),
         {:ok, assertion} <- decode_assertion(assertion_raw) do
      {:ok,
       %SAML.Response{
         version: version,
         issue_instant: issue_instant,
         destination: destination,
         issuer: issuer,
         status: status |> status_code_map(),
         assertion: assertion
       }}
    end
  end
end
