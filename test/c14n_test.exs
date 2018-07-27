defmodule SAML.C14NTest do
  use ExUnit.Case
  import SAML.XMerl.Record
  import SAML.XMerl.C14N

  test "canon name" do
    assert 'urn:foo:Blah' ==
             canon_name('foo', 'Blah', xml_namespace(nodes: [{'foo', :"urn:foo:"}]))

    assert 'urn:foo:Blah' =
             canon_name('foo', 'Blah', xml_namespace(nodes: [{'foo', :"urn:foo:"}]))

    assert {:ns_not_found, _, _} = catch_error(canon_name('foo', 'Blah', xml_namespace()))
    'urn:bar:Blah' = canon_name('bar', 'Blah', xml_namespace(nodes: [{'bar', :"urn:bar:"}]))
  end

  test "canon name attr" do
    assert 'urn:foo:Blah' =
             canon_name(
               xml_attribute(
                 name: :Blah,
                 nsinfo: {'foo', 'Blah'},
                 namespace: xml_namespace(nodes: [{'foo', :"urn:foo:"}])
               )
             )
  end

  test "canon name elem" do
    assert 'urn:foo:Blah' =
             canon_name(
               xml_element(
                 name: :Blah,
                 nsinfo: {'foo', 'Blah'},
                 namespace: xml_namespace(nodes: [{'foo', :"urn:foo:"}])
               )
             )
  end

  test "canon name default ns test" do
    {doc, []} =
      :xmerl_scan.string(
        '<foo:a xmlns:foo=\"urn:foo:\"><b xmlns=\"urn:bar:\"></b></foo:a>',
        namespace_conformant: true
      )

    xml_element(content: [node]) = doc
    assert 'urn:foo:a' == canon_name(doc)
    assert 'urn:bar:b' == canon_name(node)
  end

  @ns xml_namespace(nodes: [{'foo', :"urn:foo:"}, {'bar', :"urn:bar:"}])
  test "needed_ns (1)" do
    assert ['bar', 'foo'] =
             SAML.Utils.build_nsinfo(
               @ns,
               xml_element(
                 name: :"foo:Blah",
                 attributes: [
                   xml_attribute(name: :"bar:name", value: 'foo')
                 ]
               )
             )
             |> needed_ns([])
             |> Enum.sort()
  end

  test "needed_ns (2)" do
    assert ['bar'] =
             SAML.Utils.build_nsinfo(
               @ns,
               xml_element(
                 name: :Blah,
                 attributes: [
                   xml_attribute(name: :"bar:name", value: 'foo')
                 ]
               )
             )
             |> needed_ns([])
  end

  test "needed_ns (3)" do
    assert [] =
             SAML.Utils.build_nsinfo(
               @ns,
               xml_element(
                 name: :Blah,
                 attributes: [
                   xml_attribute(
                     name: :name,
                     value: 'foo'
                   )
                 ],
                 content: [
                   xml_element(name: :"foo:InnerBlah")
                 ]
               )
             )
             |> needed_ns([])
  end

  test "needed_ns (4)" do
    e = SAML.Utils.build_nsinfo(@ns, xml_element(name: :Blah))
    assert [] = needed_ns(e, [])
    assert [] = needed_ns(e, ['foo'])
  end

  test "needed_ns (5)" do
    {e, []} =
      :xmerl_scan.string(
        '<foo:a xmlns:foo=\"urn:foo:\" xmlns:bar=\"urn:bar:\"><foo:b bar:nothing=\"something\">foo</foo:b></foo:a>',
        namespace_conformant: true
      )

    ['foo'] = needed_ns(e, [])
    ['bar', 'foo'] = needed_ns(e, ['bar'])
  end

  test "xml_safe_string" do
    assert 'foo' = xml_safe_string(:foo)
    assert 'foo \ngeorge' = xml_safe_string("foo \ngeorge")

    assert 'foo &lt;&#x5;&gt; = &amp; help' =
             ['foo <', 5, '> = & help'] |> List.flatten() |> xml_safe_string()

    assert '&#xE;' = xml_safe_string(<<14>>)
    assert '"foo"' = xml_safe_string('"foo"')
    assert 'test&#xD;\n' = xml_safe_string('test\r\n')
  end

  test "xml_safe_string with utf8" do
    string = "バカの名前" |> to_charlist()
    ^string = xml_safe_string(string)
  end

  test "c14n_3_1" do
    {doc, _} =
      :xmerl_scan.string(
        '<?xml version=\"1.0\"?>\n\n<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n<doc>Hello, world!<!-- Comment 1 --></doc>\n\n<?pi-without-data     ?>\n\n<!-- Comment 2 -->\n\n<!-- Comment 3 -->',
        namespace_conformant: true,
        document: true
      )

    without_comments =
      '<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>'

    assert without_comments == c14n(doc, false)
  end

  test "c14n_3_2" do
    {doc, _} =
      :xmerl_scan.string(
        '<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>',
        namespace_conformant: true,
        document: true
      )

    target =
      '<doc>\n   <clean>   </clean>\n   <dirty>   A   B   </dirty>\n   <mixed>\n      A\n      <clean>   </clean>\n      B\n      <dirty>   A   B   </dirty>\n      C\n   </mixed>\n</doc>'

    assert target == c14n(doc, true)
  end

  test "c14n_3_3" do
    {doc, _} =
      :xmerl_scan.string(
        '<!DOCTYPE doc [<!ATTLIST e9 attr CDATA \"default\">]>\n<doc>\n   <e1   />\n   <e2   ></e2>\n   <e3   name = \"elem3\"   id=\"elem3\"   />\n   <e4   name=\"elem4\"   id=\"elem4\"   ></e4>\n   <e5 a:attr=\"out\" b:attr=\"sorted\" attr2=\"all\" attr=\"I\'m\"\n      xmlns:b=\"http://www.ietf.org\"\n      xmlns:a=\"http://www.w3.org\"\n      xmlns=\"http://example.org\"/>\n   <e6 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\" xmlns:a=\"http://www.w3.org\">\n            <e9 xmlns=\"\" xmlns:a=\"http://www.ietf.org\"/>\n         </e8>\n      </e7>\n   </e6>\n</doc>',
        namespace_conformant: true,
        document: true
      )

    target =
      '<doc>\n   <e1></e1>\n   <e2></e2>\n   <e3 id=\"elem3\" name=\"elem3\"></e3>\n   <e4 id=\"elem4\" name=\"elem4\"></e4>\n   <e5 xmlns=\"http://example.org\" xmlns:a=\"http://www.w3.org\" xmlns:b=\"http://www.ietf.org\" attr=\"I\'m\" attr2=\"all\" b:attr=\"sorted\" a:attr=\"out\"></e5>\n   <e6>\n      <e7 xmlns=\"http://www.ietf.org\">\n         <e8 xmlns=\"\">\n            <e9></e9>\n         </e8>\n      </e7>\n   </e6>\n</doc>'

    assert target == c14n(doc, true)
  end

  test "c14_3_4" do
    {doc, _} =
      :xmerl_scan.string(
        '<!DOCTYPE doc [\n<!ATTLIST normId id ID #IMPLIED>\n<!ATTLIST normNames attr NMTOKENS #IMPLIED>\n]>\n<doc>\n   <text>First line&#x0d;&#10;Second line</text>\n   <value>&#x32;</value>\n   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\n   <compute expr=\'value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"\'>valid</compute>\n   <norm attr=\' &apos;   &#x20;&#13;&#xa;&#9;   &apos; \'/>\n   <normNames attr=\'   A   &#x20;&#13;&#xa;&#9;   B   \'/>\n   <normId id=\' &apos;   &#x20;&#13;&#xa;&#9;   &apos; \'/>\n</doc>',
        namespace_conformant: true,
        document: true
      )

    target =
      '<doc>\n   <text>First line\n\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;"0" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;">valid</compute>\n   <norm attr=" \'    &#xD;&#xA;&#x9;   \' "></norm>\n   <normNames attr="A  &#xD;&#xA;&#x9; B"></normNames>\n   <normId id=\"\'  &#xD;&#xA;&#x9; \'\"></normId>\n</doc>'

    assert target == c14n(doc, true)
  end

  test "default_ns" do
    {doc, _} =
      :xmerl_scan.string(
        '<foo:a xmlns:foo=\"urn:foo:\"><b xmlns=\"urn:bar:\"><c xmlns=\"urn:bar:\" /></b><c xmlns=\"urn:bar:\"><d /></c><foo:e><f xmlns=\"urn:foo:\"><foo:x>blah</foo:x></f></foo:e></foo:a>',
        namespace_conformant: true
      )

    target =
      '<foo:a xmlns:foo=\"urn:foo:\"><b xmlns=\"urn:bar:\"><c></c></b><c xmlns=\"urn:bar:\"><d></d></c><foo:e><f xmlns=\"urn:foo:\"><foo:x>blah</foo:x></f></foo:e></foo:a>'

    assert target == c14n(doc, true)

    {doc, _} =
      :xmerl_scan.string(
        '<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_83dbf3f1-53c2-4f49-b294-7c19cbf2b77b\" Version=\"2.0\" IssueInstant=\"2013-10-30T11:15:47.517Z\" Destination=\"https://10.10.18.25/saml/consume\"><Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" ID=\"_debe5f4e-4343-4f95-b997-89db5a483202\" IssueInstant=\"2013-10-30T11:15:47.517Z\"><Issuer>foo</Issuer><Subject><NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"/><SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><SubjectConfirmationData NotOnOrAfter=\"2013-10-30T12:15:47.517Z\" Recipient=\"https://10.10.18.25/saml/consume\"/></SubjectConfirmation></Subject></Assertion></saml2p:Response>',
        namespace_conformant: true
      )

    target =
      '<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" Destination=\"https://10.10.18.25/saml/consume\" ID=\"_83dbf3f1-53c2-4f49-b294-7c19cbf2b77b\" IssueInstant=\"2013-10-30T11:15:47.517Z\" Version=\"2.0\"><Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_debe5f4e-4343-4f95-b997-89db5a483202\" IssueInstant=\"2013-10-30T11:15:47.517Z\" Version=\"2.0\"><Issuer>foo</Issuer><Subject><NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"></NameID><SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><SubjectConfirmationData NotOnOrAfter=\"2013-10-30T12:15:47.517Z\" Recipient=\"https://10.10.18.25/saml/consume\"></SubjectConfirmationData></SubjectConfirmation></Subject></Assertion></saml2p:Response>'

    assert target == c14n(doc, true)
  end

  test "c14n_incls_test" do
    {doc, []} =
      :xmerl_scan.string(
        '<foo:a xmlns:foo=\"urn:foo:\" xmlns:bar=\"urn:bar:\"><foo:b bar:nothing=\"something\">foo</foo:b></foo:a>',
        namespace_conformant: true
      )

    target =
      '<foo:a xmlns:foo=\"urn:foo:\"><foo:b xmlns:bar=\"urn:bar:\" bar:nothing=\"something\">foo</foo:b></foo:a>'

    assert target == c14n(doc, false)

    target =
      '<foo:a xmlns:bar=\"urn:bar:\" xmlns:foo=\"urn:foo:\"><foo:b bar:nothing=\"something\">foo</foo:b></foo:a>'

    assert target == c14n(doc, false, ['bar'])
  end
end
