defmodule SAML.Utils do
  import SAML.XMerl.Record

  def build_nsinfo(ns, attr = xml_attribute(name: name)) do
    case :string.tokens(:erlang.atom_to_list(name), ':') do
      [ns_prefix, rest] ->
        xml_attribute(
          attr,
          namespace: ns,
          nsinfo: {ns_prefix, rest}
        )

      _ ->
        xml_attribute(attr, namespace: ns)
    end
  end

  def build_nsinfo(ns, elem = xml_element(name: name, content: children, attributes: attrs)) do
    elem2 =
      case :string.tokens(:erlang.atom_to_list(name), ':') do
        [ns_prefix, rest] -> xml_element(elem, namespace: ns, nsinfo: {ns_prefix, rest})
        _ -> xml_element(namespace: ns)
      end

    xml_element(
      elem2,
      attributes: for(attr <- attrs, do: build_nsinfo(ns, attr)),
      content: for(child <- children, do: build_nsinfo(ns, child))
    )
  end

  def build_nsinfo(_ns, other), do: other

  def int(s), do: String.to_integer(s)

  # def saml_to_datetime(stamp) when is_list(stamp), do: saml_to_datetime(to_string(stamp))

  def saml_to_datetime(<<
        y::binary-size(4),
        "-",
        mo::binary-size(2),
        "-",
        d::binary-size(2),
        "T",
        h::binary-size(2),
        ":",
        mi::binary-size(2),
        ":",
        s::binary-size(2),
        rest::binary
      >>) do
    "Z" = String.last(rest)
    {{int(y), int(mo), int(d)}, {int(h), int(mi), int(s)}}
  end

  def datetime_to_saml({{y, mo, d}, {h, mi, s}}) do
    "~4.10.0B-~2.10.0B-~2.10.0BT~2.10.0B:~2.10.0B:~2.10.0BZ"
    |> :io_lib.format([y, mo, d, h, mi, s])
    |> to_string
  end
end
