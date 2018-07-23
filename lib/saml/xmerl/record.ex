defmodule SAML.XMerl.Record do
  require Record
  import Record, only: [defrecord: 3, extract: 2]

  defrecord :xml_element, :xmlElement, extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl")

  defrecord :xml_attribute,
            :xmlAttribute,
            extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")

  defrecord :xml_text, :xmlText, extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl")
end
