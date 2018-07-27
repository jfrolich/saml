defmodule SAML.XMerl.Record do
  require Record
  import Record, only: [defrecord: 3, extract: 2]

  defrecord :xml_namespace,
            :xmlNamespace,
            extract(:xmlNamespace, from_lib: "xmerl/include/xmerl.hrl")

  defrecord :xml_document,
            :xmlDocument,
            extract(:xmlDocument, from_lib: "xmerl/include/xmerl.hrl")

  defrecord :xml_comment, :xmlComment, extract(:xmlComment, from_lib: "xmerl/include/xmerl.hrl")
  defrecord :xml_pi, :xmlPI, extract(:xmlPI, from_lib: "xmerl/include/xmerl.hrl")

  @type xml_namespace ::
          record(
            :xml_namespace,
            default: list,
            nodes: list
          )

  defrecord :xml_attribute,
            :xmlAttribute,
            extract(:xmlAttribute, from_lib: "xmerl/include/xmerl.hrl")

  @type xml_attribute ::
          record(
            :xml_attribute,
            name: atom,
            expanded_name: atom | {charlist, atom},
            nsinfo: {charlist, charlist} | [],
            namespace: xml_namespace,
            parents: [{atom, integer}],
            pos: integer,
            language: charlist,
            value: IOlist | atom | integer
          )

  defrecord :xml_element, :xmlElement, extract(:xmlElement, from_lib: "xmerl/include/xmerl.hrl")

  @type xml_element ::
          record(
            :xml_element,
            name: atom,
            expanded_name: charlist | {charlist, charlist},
            nsinfo: {charlist, charlist} | [],
            namespace: xml_namespace,
            parents: [{atom, integer}],
            pos: integer,
            attributes: [xml_attribute],
            content: list,
            language: charlist,
            xmlbase: charlist,
            elementdef: :undeclared | :prolog | :external | :element
          )

  defrecord :xml_text, :xmlText, extract(:xmlText, from_lib: "xmerl/include/xmerl.hrl")
end
