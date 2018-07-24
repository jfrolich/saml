defmodule SAML.XPath do
  alias SAML.XMerl
  import XMerl.Record
  import Record

  defmacro xpath_generic(xml, ns, xpath, trans_fun, target_type, not_found_ret) do
    quote do
      case :xmerl_xpath.string(unquote(xpath), unquote(xml), {:namespace, unquote(ns)}) do
        [unquote(target_type)(value: v)] ->
          {:ok, unquote(trans_fun).(v)}

        _ ->
          unquote(not_found_ret)
      end
    end
  end

  defmacro xpath_generic(xml, ns, xpath, target_type, not_found_ret) do
    quote do
      case :xmerl_xpath.string(unquote(xpath), unquote(xml), [{:namespace, unquote(ns)}]) do
        [unquote(target_type)(value: v)] ->
          {:ok, v}

        _ ->
          unquote(not_found_ret)
      end
    end
  end

  defp to_nil_string(nil), do: nil
  defp to_nil_string(str) when is_list(str), do: to_string(str)
  defp to_nil_string(str) when is_binary(str), do: str

  def list(xml, ns, xpath) do
    case :xmerl_xpath.string(xpath, xml, [{:namespace, ns}]) do
      v when is_list(v) -> v
    end
  end

  def attr_required(xml, ns, xpath, error) do
    with {:ok, value} <- xpath_generic(xml, ns, xpath, :xml_attribute, {:error, error}) do
      {:ok, to_nil_string(value)}
    end
  end

  # def attr_required(xml, ns, xpath, trans_fun, error) do
  #   xpath_generic(xml, ns, xpath, trans_fun, :xml_attribute, {:error, error})
  # end

  def attr(xml, ns, xpath, default) do
    {:ok, value} = xpath_generic(xml, ns, xpath, :xml_attribute, {:ok, default})

    to_nil_string(value)
  end

  def attr(xml, ns, xpath, trans_fun, default) do
    {:ok, value} = xpath_generic(xml, ns, xpath, trans_fun, :xml_attribute, {:ok, default})
    to_nil_string(value)
  end

  def text(xml, ns, xpath, default) do
    {:ok, text} = xpath_generic(xml, ns, xpath, :xml_text, {:ok, default})
    to_nil_string(text)
  end

  def text_required(xml, ns, xpath, error) do
    with {:ok, text} <- xpath_generic(xml, ns, xpath, :xml_text, {:error, error}) do
      {:ok, to_nil_string(text)}
    end
  end

  defmacro recurse(xml, ns, xpath, default) do
    quote do
      {:ok, value} =
        case :xmerl_xpath.string(unquote(xpath), unquote(xml), [{:namespace, unquote(ns)}]) do
          [e = xml_element()] ->
            {:ok, e}

          _ ->
            {:ok, unquote(default)}
        end

      value
    end
  end
end
