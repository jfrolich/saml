defmodule SAML.XMerl.C14N do
  import SAML.XMerl.Record

  @moduledoc """

  Functions for performing XML canonicalisation (C14n), as specified
  at http://www.w3.org/TR/xml-c14n .

  These routines work on xmerl data structures (see the xmerl user guide
  for details).

  This is quite a direct port of `xmerl_c14n` of `esaml`, and it's pretty sloppy

  TODO: Refactor this
  """

  def canon_name(ns, name, nsp) do
    ns_part_raw =
      case ns do
        :empty ->
          xml_namespace(nsp, :default)

        [] ->
          xml_namespace(nsp, :default)

        _ ->
          case :proplists.get_value(ns, xml_namespace(nsp, :nodes)) do
            :undefined -> :erlang.error({:ns_not_found, ns, nsp})
            uri -> :erlang.atom_to_list(uri)
          end
      end

    ns_part = if is_atom(ns_part_raw), do: :erlang.atom_to_list(ns_part_raw), else: ns_part_raw
    name_part = if is_atom(name), do: :erlang.atom_to_list(name), else: name

    :lists.flatten([ns_part | name_part])
  end

  def canon_name(xml_attribute(name: name, nsinfo: exp, namespace: nsp)) do
    case exp do
      {ns, nme} -> canon_name(ns, nme, nsp)
      _ -> canon_name([], name, nsp)
    end
  end

  def canon_name(xml_element(name: name, nsinfo: exp, namespace: nsp)) do
    case exp do
      {ns, nme} -> canon_name(ns, nme, nsp)
      _ -> canon_name([], name, nsp)
    end
  end

  def xml_safe_string(term) do
    xml_safe_string(term, false)
  end

  def xml_safe_string(atom, quotes) when is_atom(atom),
    do: xml_safe_string(:erlang.atom_to_list(atom), quotes)

  def xml_safe_string(bin, quotes) when is_binary(bin),
    do: xml_safe_string(:erlang.binary_to_list(bin), quotes)

  def xml_safe_string([], _), do: []

  def xml_safe_string(str, quotes) when is_list(str) do
    [next | rest] = str

    cond do
      not quotes && [next] === '\n' ->
        [next | xml_safe_string(rest, quotes)]

      next < 32 ->
        :lists.flatten([
          '&#x' ++ :erlang.integer_to_list(next, 16) ++ ';' | xml_safe_string(rest, quotes)
        ])

      quotes && [next] === '"' ->
        :lists.flatten(['&quot;' | xml_safe_string(rest, quotes)])

      [next] === '&' ->
        :lists.flatten(['&amp;' | xml_safe_string(rest, quotes)])

      [next] === '<' ->
        :lists.flatten(['&lt;' | xml_safe_string(rest, quotes)])

      not quotes && [next] === '>' ->
        :lists.flatten(['&gt;' | xml_safe_string(rest, quotes)])

      true ->
        [next | xml_safe_string(rest, quotes)]
    end
  end

  def xml_safe_string(term, quotes), do: xml_safe_string(:io_lib.format('~p', [term]), quotes)

  def needed_ns(xml_element(nsinfo: ns_info, attributes: attrs), incl_ns) do
    needed_ns =
      case ns_info do
        {nas, _} -> [nas]
        _ -> []
      end

    # show through namespaces that apply at the bottom level? this part of the spec is retarded
    :lists.foldl(
      fn attr, needed ->
        case xml_attribute(attr, :nsinfo) do
          {'xmlns', prefix} ->
            case :lists.member(prefix, incl_ns) do
              true -> [prefix | needed]
              _ -> needed
            end

          {ns, _name} ->
            case :lists.member(ns, needed) do
              true -> needed
              _ -> [ns | needed]
            end

          _ ->
            needed
        end
      end,
      needed_ns,
      attrs
    )
  end

  defp attr_lte(attr_a, attr_b) do
    a = canon_name(attr_a)
    b = canon_name(attr_b)

    prefixed_a =
      case xml_attribute(attr_a, :nsinfo) do
        {_, _} -> true
        _ -> false
      end

    prefixed_b =
      case xml_attribute(attr_b, :nsinfo) do
        {_, _} -> true
        _ -> false
      end

    cond do
      prefixed_a and not prefixed_b -> false
      not prefixed_a and prefixed_b -> true
      true -> a <= b
    end
  end

  defp clean_sort_attrs(attrs) do
    attrs
    |> Enum.filter(fn
      xml_attribute(nsinfo: {'xmlns', _}) -> false
      xml_attribute(name: :xmlns) -> false
      _ -> true
    end)
    |> Enum.sort(&attr_lte(&1, &2))
  end

  def c14n(xml_text(value: text), _known_ns, _active_ns, _comments, _incl_ns, acc) do
    [xml_safe_string(text) | acc]
  end

  def c14n(xml_comment(value: text), _known_ns, _active_ns, true, _incl_ns, acc) do
    ['-->', xml_safe_string(text), '<!--' | acc]
  end

  def c14n(xml_pi(name: name, value: value), _known_ns, _active_ns, _comments, _incl_ns, acc) do
    name_string = if is_atom(name), do: :erlang.atom_to_list(name), else: :string.strip(name)

    case :string.strip(value) do
      [] -> ['?>', name_string, '<?' | acc]
      _ -> ['?>', value, ' ', name_string, '<?' | acc]
    end
  end

  def c14n(xml_document(content: children), known_ns, active_ns, comments, incl_ns, acc) do
    case :lists.foldl(
           fn child, acc_in ->
             case c14n(child, known_ns, active_ns, comments, incl_ns, acc_in) do
               ^acc_in -> acc_in
               other -> ['\n' | other]
             end
           end,
           acc,
           children
         ) do
      ['\n' | rest] -> rest
      other -> other
    end
  end

  def c14n(
        xml_attribute(nsinfo: ns_info, name: name, value: value),
        _known_ns,
        active_ns,
        _comments,
        _incl_ns,
        acc
      ) do
    case ns_info do
      {ns, n_name} ->
        case :lists.member(ns, active_ns) do
          true -> ['"', xml_safe_string(value, true), '="', n_name, ':', ns, ' ' | acc]
          _ -> :erlang.error('attribute namespace is not active')
        end

      _ ->
        ['"', xml_safe_string(value, true), '="', :erlang.atom_to_list(name), ' ' | acc]
    end
  end

  def c14n(elem = xml_element(), known_ns_in, active_ns_in, comments, incl_ns, acc) do
    namespace = xml_element(elem, :namespace)
    default = xml_namespace(namespace, :default)

    {active_ns, parent_default} =
      case active_ns_in do
        [{:default, p} | rest] -> {rest, p}
        other -> {other, :""}
      end

    # add any new namespace this element has that we haven't seen before
    known_ns =
      :lists.foldl(
        fn {ns, uri}, nss ->
          case :proplists.is_defined(ns, nss) do
            true -> nss
            _ -> [{ns, :erlang.atom_to_list(uri)} | nss]
          end
        end,
        known_ns_in,
        xml_namespace(namespace, :nodes)
      )

    needed_ns = needed_ns(elem, incl_ns)

    attrs = clean_sort_attrs(xml_element(elem, :attributes))

    # we need to append any xmlns: that our parent didn't have (ie, aren't in ActiveNS) but
    # that we need
    new_ns = needed_ns -- active_ns
    new_active_ns = active_ns ++ new_ns

    # the opening tag
    acc =
      case xml_element(elem, :nsinfo) do
        {e_ns, e_name} ->
          [e_name, ':', e_ns, '<' | acc]

        _ ->
          [:erlang.atom_to_list(xml_element(elem, :name)), '<' | acc]
      end

    # xmlns definitions
    {acc, final_active_ns} =
      cond do
        not (default === []) and not (default === parent_default) ->
          {['"', xml_safe_string(default, true), ' xmlns="' | acc],
           [{:default, default} | new_active_ns]}

        not (default === []) ->
          {acc, [{:default, default} | new_active_ns]}

        true ->
          {acc, new_active_ns}
      end

    acc =
      :lists.foldl(
        fn ns, acc_in ->
          [
            '"',
            xml_safe_string(:proplists.get_value(ns, known_ns, ''), true),
            '="',
            ns,
            ':',
            ' xmlns' | acc_in
          ]
        end,
        acc,
        :lists.sort(new_ns)
      )

    # any other attributes
    acc =
      :lists.foldl(
        fn attr, acc_in ->
          c14n(attr, known_ns, final_active_ns, comments, incl_ns, acc_in)
        end,
        acc,
        attrs
      )

    # close the opening tag
    acc = ['>' | acc]

    # now accumulate all our children
    acc =
      :lists.foldl(
        fn child, acc_in ->
          c14n(child, known_ns, final_active_ns, comments, incl_ns, acc_in)
        end,
        acc,
        xml_element(elem, :content)
      )

    # and finally add the close tag
    case xml_element(elem, :nsinfo) do
      {ns, name} -> ['>', name, ':', ns, '</' | acc]
      _ -> ['>', :erlang.atom_to_list(xml_element(elem, :name)), '</' | acc]
    end
  end

  def c14n(_elem, _known_ns, _active_ns, _comments, _incl_ns, acc) do
    acc
  end

  def c14n(elem, comments), do: c14n(elem, comments, [])

  def c14n(elem, comments, inclusive_ns),
    do: :lists.flatten(:lists.reverse(c14n(elem, [], [], comments, inclusive_ns, [])))
end
