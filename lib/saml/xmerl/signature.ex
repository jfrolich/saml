defmodule SAML.XMerl.Signature do
  import __MODULE__.Record
  import SAML.XMerl.Record

  @moduledoc """
  Functions for performing XML digital signature generation and
  verification, as specified at http://www.w3.org/TR/xmldsig-core/ .

  These routines work on xmerl data structures (see the xmerl user guide
  for details).

  Currently only RSA + SHA1|SHA256 signatures are supported, in the typical
  enveloped mode.
  """

  defp strip(xml_document(content: children) = doc) do
    children =
      Enum.map(children, fn
        element = xml_element() -> strip(element)
        element -> element
      end)

    xml_document(doc, content: children)
  end

  defp strip(xml_element(content: children) = elem) do
    children =
      Enum.filter(
        children,
        &case SAML.XMerl.C14N.canon_name(&1) do
          'http://www.w3.org/2000/09/xmldsig#Signature' -> false
          _name -> true
        end
      )

    xml_element(elem, content: children)
  end

  @sha1_url 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
  @sha256_url 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
  defp signature_props(@sha1_url), do: signature_props(:rsa_sha1)

  defp signature_props(:rsa_sha1) do
    hash_function = :sha
    digest_method = 'http://www.w3.org/2000/09/xmldsig#sha1'
    url = @sha1_url
    {hash_function, digest_method, url}
  end

  defp signature_props(@sha256_url) do
    signature_props(:rsa_sha256)
  end

  defp signature_props(:rsa_sha256) do
    hash_function = :sha256
    digest_method = 'http://www.w3.org/2001/04/xmlenc#sha256'
    url = @sha256_url
    {hash_function, digest_method, url}
  end

  def sign(element_in, private_key = rsa_private_key(), cert_bin) when is_binary(cert_bin) do
    sign(element_in, private_key, cert_bin, 'http://www.w3.org/2000/09/xmldsig#rsa-sha1')
  end

  def sign(element_in, private_key = rsa_private_key(), cert_bin, sig_method)
      when is_binary(cert_bin) do
    element_strip = strip(element_in)

    {element, id} =
      case :lists.keyfind(:ID, 2, xml_element(element_strip, :attributes)) do
        xml_attribute(value: cap_id) ->
          {element_strip, cap_id}

        _ ->
          case :lists.keyfind(:id, 2, xml_element(element_strip, :attributes)) do
            xml_attribute(value: low_id) ->
              {element_strip, low_id}

            _ ->
              new_id = to_charlist(UUID.uuid1())
              attr = xml_attribute(name: :ID, value: new_id, namespace: xml_namespace())
              new_attrs = [attr | xml_element(element_strip, :attributes)]
              elem = xml_element(attributes: new_attrs)
              {elem, new_id}
          end
      end

    {hash_function, digest_method, signature_method_algorithm} = signature_props(sig_method)

    canon_xml = SAML.XMerl.C14N.c14n(element)
  end
end
