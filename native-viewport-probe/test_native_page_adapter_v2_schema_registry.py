"""Offline contract tests only; no provider, process, device or network calls."""
import base64
import hashlib
import unittest
from dataclasses import replace

import native_page_adapter_v2_schema_registry as r


class CodecEngineTests(unittest.TestCase):
    def setUp(self):
        self.reg = r.compile_registry((r.schema("CodecFixtureV2", "S", "SMALL",
            {"a": r.Text(128), "n": r.Integer(), "z": r.BOOL}),))
        self.value = {"authority": r.PREFIX + "schema/CodecFixtureV2",
                      "schemaVersion": 2, "a": '"\\\né/', "n": 0, "z": False}

    def test_exact_codec_known_answer(self):
        raw = r.canonical(self.value)
        self.assertEqual(len(raw), 125)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            "d26529a123460be8b78ac06e8b527cc9d02a634171e38337690c00815a166a8f")
        self.assertEqual(r.body_digest("CodecFixtureV2", raw, self.reg),
            "d12219cf9cdd2b3f84cc4e9c6bf57c0b7553c5ffe928d6acad68653f0c0a5f93")
        self.assertEqual(r.validate_body("CodecFixtureV2", raw, self.reg), self.value)

    def test_noncanonical_and_duplicate_inputs(self):
        for raw in (b'{"a":1,"a":2}', b'{"a": 1}', b'{"b":0,"a":1}',
                    b'{"a":1.0}', b'{"a":NaN}', b'{"a":-0}',
                    b'{"a":"\\n"}', b'{"a":"\\u0061"}', b'{}\n',
                    b'\xef\xbb\xbf{}', b'{"a":"\xc0\xaf"}'):
            with self.subTest(raw=raw), self.assertRaises(r.ContractError):
                r.decode_canonical(raw)

    def test_exact_types_and_unknown_fields(self):
        class IntAlias(int): pass
        for bad in (None, 1, [], {}, IntAlias(0)):
            value = dict(self.value, z=bad)
            with self.subTest(bad=type(bad).__name__), self.assertRaises(r.ContractError):
                r.validate_body("CodecFixtureV2", r.canonical(value), self.reg)
        for key in tuple(self.value):
            value = self.value.copy()
            del value[key]
            with self.subTest(missing=key), self.assertRaises(r.ContractError):
                r.validate_body("CodecFixtureV2", r.canonical(value), self.reg)
        with self.assertRaises(r.ContractError):
            r.validate_body("CodecFixtureV2", r.canonical(dict(self.value, extra=0)), self.reg)
        with self.assertRaises(r.ContractError):
            r.require_schema("UnregisteredV2", self.reg)

    def test_unicode_escape_and_structure_bounds(self):
        for value in ("\x00", "\ud800", "e\u0301"):
            with self.assertRaises(r.ContractError):
                r.canonical(value)
        with self.assertRaises(r.ContractError):
            r.decode_canonical(b"[" * 19 + b"]" * 19)
        for raw in (b"", b"{}"):
            with self.assertRaises(r.ContractError):
                r.decode_canonical(raw, 1)
        self.assertEqual(r.canonical("\x01"), b'"\\u0001"')

    def test_encoded_max_codec_fixture(self):
        raw = r.canonical(dict(self.value, a="\x01"*128, n=r.MAX_SAFE_INTEGER))
        self.assertEqual(len(raw), 895)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            "a68ba43ce45fa4c9338e4bcdcd00fff6387cfe5b83f3bede36390c8ccf8fb74f")
        r.validate_body("CodecFixtureV2", raw, self.reg)
        with self.assertRaises(r.ContractError):
            r.validate_body("CodecFixtureV2",
                r.canonical(dict(self.value, a="\x01"*129)), self.reg)

    def test_ld_count_order_and_purpose_separation(self):
        d = r.domain("CodecFixtureV2", "body-hash", self.reg)
        one = r.ld(d, (b"a", b"bc"))
        self.assertNotEqual(one, r.ld(d, (b"ab", b"c")))
        self.assertNotEqual(one, r.ld(d, (b"bc", b"a")))
        self.assertNotEqual(one, r.ld(d+"x", (b"a", b"bc")))
        for args in ((d, [b"a"]), (d, ("a",)), (1, ())):
            with self.assertRaises(r.ContractError):
                r.ld(*args)
        with self.assertRaises(r.ContractError):
            r.domain("CodecFixtureV2", "signature", self.reg)

    def test_base64_and_decimal_boundaries(self):
        reg = r.compile_registry((r.schema("PrimitiveFixtureV2", "S", "SMALL",
            {"nonce":r.Base64(12), "tag":r.Base64(32), "n":r.SIGNED_I64}),))
        value = {"authority":r.PREFIX+"schema/PrimitiveFixtureV2", "schemaVersion":2,
            "nonce":base64.b64encode(bytes(12)).decode(),
            "tag":base64.b64encode(bytes(32)).decode(), "n":"0"}
        for n in ("-9223372036854775808", "-1", "0", "1", "9223372036854775807"):
            r.validate_body("PrimitiveFixtureV2",r.canonical(dict(value,n=n)),reg)
        for n in ("+1","01","-0"," 1","9223372036854775808",1,True):
            with self.assertRaises(r.ContractError):
                r.validate_body("PrimitiveFixtureV2",r.canonical(dict(value,n=n)),reg)
        for tag in (value["tag"][:-2]+"B=", value["tag"]+"=", "", 0):
            with self.assertRaises(r.ContractError):
                r.validate_body("PrimitiveFixtureV2",r.canonical(dict(value,tag=tag)),reg)

    def test_registry_and_instance_dependency_shapes(self):
        self.assertEqual(r.validate_dependency_dag({"P":(), "lane":("P",),
             "E":("P","lane")}), ("P","lane","E"))
        for graph in ({"P":("E",),"E":("P",)}, {"P":("missing",)},
                      {"P":[]}, {"P":(),"E":("P","P")}):
            with self.assertRaises(r.ContractError):
                r.validate_dependency_dag(graph)
        with self.assertRaises(r.ContractError):
            r.compile_registry((self.reg["CodecFixtureV2"],)*2)
        with self.assertRaises(r.ContractError):
            r.compile_registry((r.schema("CycleV2","S","SMALL",
                                         {"child":r.Object("CycleV2")}),))
        with self.assertRaises(r.ContractError):
            r.compile_registry((r.schema("UnknownRefV2","S","SMALL",
                                         {"child":r.Ref("MissingV2")}),))



    def test_compile_rejects_malformed_descriptors(self):
        cases=(r.Type("integer",()),r.Type("nullable",()),r.Type("vector",(r.Integer(),0)),
            r.Type("hash",("ignored",)),r.Integer(2,1),r.Integer(-9007199254740992,0),
            r.Vector(r.Integer(),0,1),r.Text(8,"unknown"),r.Text(0),r.Base64(-1),
            r.Enum(),r.Enum("x","x"),r.Const(["mutable"]))
        for index,member in enumerate(cases):
            with self.subTest(index=index),self.assertRaises(r.ContractError):
                r.compile_registry((r.schema("BadDescriptorV2","S","SMALL",{"value":member}),))

    def test_compile_revalidates_direct_schema_instances(self):
        base=r.schema("DirectFixtureV2","S","SMALL",{"value":r.Integer()})
        cases=(replace(base,name="bad"),replace(base,phase="X"),
            replace(base,size_class="UNKNOWN"),replace(base,purposes=()),
            replace(base,purposes=("body-hash","bad/purpose")),replace(base,key_role=0),
            replace(base,key_role="unregistered"),replace(base,signature_profile="bad"),
            replace(base,envelope_bodies=("MissingV2",)),
            replace(base,fields=tuple(p for p in base.fields if p[0]!="authority")),
            replace(base,fields=tuple(sorted(base.fields+(("é",r.Text()),)))))
        for spec in cases:
            with self.subTest(name=spec.name),self.assertRaises(r.ContractError):
                r.compile_registry((spec,))

    def test_rule_compile_signatures(self):
        fields={"count":r.Integer(0,3),"items":r.Vector(r.Integer(0,9),3),
            "left":r.Integer(0,9),"right":r.Integer(0,9),"total":r.Integer(0,18),
            "mode":r.Enum("active","inactive"),"a":r.BOOL,"b":r.BOOL}
        bad=(r.Rule("unknown",("count",)),r.Rule("length",("count",)),
            r.Rule("unique",("count",)),r.Rule("ordered",("count",)),
            r.Rule("sum",("mode","left","right")),r.Rule("clock-xor",("left","right")),
            r.Rule("less",("a","b")),r.Rule("mask",("mode",),()),
            r.Rule("mask",("mode",),("active",("missing",),())),
            r.Rule("reference-dispatch",("mode",),("not-a-pair",)))
        for rule in bad:
            with self.subTest(rule=rule.kind),self.assertRaises(r.ContractError):
                r.compile_registry((r.schema("RuleFixtureV2","S","SMALL",fields,rules=(rule,)),))
        good=r.schema("RuleFixtureV2","S","SMALL",fields,rules=(
            r.Rule("length",("count","items")),r.Rule("unique",("items",)),
            r.Rule("sum",("total","left","right")),r.Rule("range",("left","right"))))
        reg=r.compile_registry((good,))
        value={"authority":r.PREFIX+"schema/RuleFixtureV2","schemaVersion":2,
            "count":2,"items":[1,2],"left":1,"right":2,"total":3,"mode":"active","a":True,"b":False}
        r.validate_body("RuleFixtureV2",r.canonical(value),reg)
        with self.assertRaises(r.ContractError):
            r.validate_body("RuleFixtureV2",r.canonical(dict(value,items=[1,1])),reg)

    def test_compiler_detaches_descriptor_graph(self):
        member=r.Integer(0,3)
        original=r.schema("DetachedFixtureV2","S","SMALL",{"value":member})
        reg=r.compile_registry((original,))
        object.__setattr__(member,"args",(0,99))
        object.__setattr__(original,"purposes",("body-hash","signature"))
        value={"authority":r.PREFIX+"schema/DetachedFixtureV2","schemaVersion":2,"value":99}
        with self.assertRaises(r.ContractError):
            r.validate_body("DetachedFixtureV2",r.canonical(value),reg)
        with self.assertRaises(r.ContractError):
            r.domain("DetachedFixtureV2","signature",reg)
        for spec in (replace(original,purposes=["body-hash"]),
            r.schema("MutableRuleV2","S","SMALL",{"mode":r.Enum("a","b"),
              "payload":r.Nullable(r.Text())},rules=(r.Rule("mask",("mode",),("a",["payload"],())),))):
            with self.assertRaises(r.ContractError): r.compile_registry((spec,))

    def test_canonical_uri_and_percent_aliases(self):
        reg=r.compile_registry((r.schema("UriFixtureV2","S","SMALL",{"uri":r.Text(4096,"uri")}),))
        def check(uri):
            return r.validate_body("UriFixtureV2",r.canonical({
                "authority":r.PREFIX+"schema/UriFixtureV2","schemaVersion":2,"uri":uri}),reg)
        for uri in ("file:///A","file:///A/b-c_1.~","file:///%C3%A9"): check(uri)
        for uri in ("file:///%2E%2E/secret","file:///safe/%2E/secret","file:///%41",
            "file:///%7E","file:///%FF","file:///%C0%AF","file:///e%CC%81"):
            with self.subTest(uri=uri),self.assertRaises(r.ContractError): check(uri)

    def test_literal_ld_and_canonical_byte_vectors(self):
        self.assertEqual(r.ld("D",(b"a",b"bc")),
            bytes.fromhex("00000001440000000200000000000000016100000000000000026263"))
        expected=(b'{"a":"' + bytes.fromhex("5c225c5c5c7530303061c3a92f") +
            b'","authority":"rtl-reader/native-page/adapter-v2/schema/CodecFixtureV2",'
            b'"n":0,"schemaVersion":2,"z":false}')
        self.assertEqual(r.canonical(self.value),expected)

    def test_canonical_dag_permutations_and_unhashable_members(self):
        for graph in ({"P":(),"lane":("P",),"E":("P","lane")},
            {"E":("lane","P"),"P":(),"lane":("P",)}):
            self.assertEqual(r.validate_dependency_dag(graph),("P","lane","E"))
        self.assertEqual(r.validate_dependency_dag({"B":(),"A":()}),("A","B"))
        class StrAlias(str): pass
        for graph in ({"A":([],)},{"A":({},)},{"A":(1,)},{StrAlias("A"):()}):
            with self.assertRaises(r.ContractError): r.validate_dependency_dag(graph)

    def test_phase_masks_and_reserved_fields(self):
        defs=(r.schema("PlanCoreV2","S","SMALL",{}),r.schema("ExecutionBindingBodyV2","P","SMALL",{}),
            r.schema("ContextFixtureV2","X","SMALL",{}),r.schema("StaticFixtureV2","S","SMALL",{}))
        reg=r.compile_registry(defs);h="0"*64
        for phase,p,e in (("pre-plan",None,None),("pre-E",h,None),("post-E",h,h)):
            value={"authority":r.PREFIX+"schema/ContextFixtureV2","schemaVersion":2,
                "constructionId":h,"contextPhase":phase,"planCoreSha256":p,"executionBindingSha256":e}
            r.validate_body("ContextFixtureV2",r.canonical(value),reg)
            value["executionBindingSha256"]=h if e is None else None
            with self.assertRaises(r.ContractError):
                r.validate_body("ContextFixtureV2",r.canonical(value),reg)

    def test_preparse_flat_limits_and_exact_cap_type(self):
        self.assertEqual(len(r.decode_canonical(b"["+b",".join([b"0"]*32767)+b"]",70000)),32767)
        for n in (32768,32769):
            with self.assertRaises(r.ContractError):
                r.decode_canonical(b"["+b",".join([b"0"]*n)+b"]",70000)
        for cap in (True,1.0,"1",0,-1):
            with self.assertRaises(r.ContractError): r.decode_canonical(b"0",cap)

    def test_fixture_context_restores_references_between_closed_arms(self):
        fixture=r.schema("PhaseArmFixtureV2","X","SMALL",{
            "arm":r.Enum("early","planned","active")},rules=(
                r.Rule("constant-if",("arm","contextPhase"),("early","pre-plan")),
                r.Rule("constant-if",("arm","contextPhase"),("planned","pre-E"))))
        reg=r.compile_registry((r.schema("PlanCoreV2","S","SMALL",{}),
            r.schema("ExecutionBindingBodyV2","P","SMALL",{}),fixture))
        value=r.maximum_fixture("PhaseArmFixtureV2",reg)[0]
        def make(member,path): return r._fixture_scalar(member,path,reg)
        for arm,phase,present in (("early","pre-plan",(False,False)),
                ("planned","pre-E",(True,False)),("active","post-E",(True,True)),
                ("early","pre-plan",(False,False)),("active","post-E",(True,True))):
            value["arm"]=arm
            r._fixture_apply_rules(fixture,value,reg,make)
            with self.subTest(arm=arm):
                self.assertEqual(value["contextPhase"],phase)
                self.assertEqual(tuple(value[k] is not None for k in
                    ("planCoreSha256","executionBindingSha256")),present)
                r.validate_body(fixture.name,r.canonical(value),reg)

    def test_complete_registry_compiles_and_domains_are_unique(self):
        reg=r.compile_registry(tuple(r._DEFINITIONS))
        self.assertGreaterEqual(len(reg),215)
        domains=[r.domain(name,purpose,reg) for name,spec in reg.items() for purpose in spec.purposes]
        self.assertEqual(len(domains),len(set(domains)))



class RegistryCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg=r.compile_registry(tuple(r._DEFINITIONS))
        cls.values={name:r.maximum_fixture(name,cls.reg)[0] for name in cls.reg}

    def _independent_field_maximum(self,member,path):
        """Test-local field maxima; deliberately does not execute registry rules."""
        import copy
        kind,args=member.kind,member.args
        if kind=="nullable": return self._independent_field_maximum(args[0],path)
        if kind=="object": return copy.deepcopy(self.values[args[0]])
        if kind=="choice":
            candidates=[copy.deepcopy(self.values[name]) for name in args]
            return max(candidates,key=lambda value:(len(r.canonical(value)),r.canonical(value)))
        if kind=="vector":
            return [self._independent_field_maximum(args[0],path+"/"+str(index))
                    for index in range(args[2])]
        if kind=="tuple":
            return [self._independent_field_maximum(child,path+"/"+str(index))
                    for index,child in enumerate(args)]
        if kind=="const": return args[0]
        if kind=="enum": return max(args,key=lambda value:(len(r.canonical(value)),value))
        if kind=="schema-name": return max(self.reg,key=lambda value:(len(value),value))
        if kind=="integer": return max(args,key=lambda value:(len(str(value)),value))
        if kind=="decimal": return str(max(args,key=lambda value:(len(str(value)),value)))
        if kind in ("hash","ref"): return hashlib.sha256(path.encode()).hexdigest()
        if kind=="boolean": return False
        if kind=="base64": return base64.b64encode(bytes(args[0])).decode()
        if kind=="text":
            limit,grammar=args
            if grammar=="path": return "/"+"x"*(limit-1)
            if grammar=="uri": return "file:///"+"x"*(limit-8)
            return ("\x01" if grammar in ("nfc","ascii") else "x")*limit
        self.fail("unhandled independent fixture member: "+kind)

    def _independent_seed(self,name):
        spec=self.reg[name]
        value={key:self._independent_field_maximum(member,name+"/"+key)
               for key,member in spec.fields}
        if spec.phase=="X": value["contextPhase"]="post-E"
        return value

    def test_every_schema_has_valid_measured_maximum(self):
        for name,spec in self.reg.items():
            with self.subTest(schema=name):
                value=self.values[name];raw=r.canonical(value)
                r.validate_body(name,raw,self.reg)
                self.assertLessEqual(len(raw),r.SIZE_CLASSES[spec.size_class])
                self.assertEqual(r._fixture_measure(value)[0],len(raw))
                wire,proof=r.maximum_wire_fixture(name,self.reg)
                r.decode_wire(name,wire,self.reg)
                self.assertLessEqual(len(wire),r.wire_limit(name,self.reg))
                self.assertIn(proof,("field-and-arm-extremum","encoded-class-saturated",
                    "exhaustive-cardinality-state-arm-node-budget","exhaustive-body-pairing-wire-maximum"))

    def test_document_names_and_measured_wire_corpus_match_registry(self):
        import re
        from pathlib import Path
        doc=Path(__file__).with_name("NATIVE_PAGE_PRODUCTION_ADAPTER_V2_DESIGN.md").read_text(encoding="utf-8")
        mentioned=set(re.findall(r"\b[A-Z][A-Za-z0-9]*V2\b",doc))
        self.assertEqual(mentioned-set(self.reg)-r.NON_WIRE_NAMES,set())
        self.assertIn("NOT CLEAN",doc)
        self.assertEqual(doc.count("<!-- BEGIN ADAPTER V2 CORPUS -->"),1)
        self.assertEqual(doc.count("<!-- END ADAPTER V2 CORPUS -->"),1)
        block=doc.split("<!-- BEGIN ADAPTER V2 CORPUS -->")[1].split("<!-- END ADAPTER V2 CORPUS -->")[0]
        actual=[line for line in block.splitlines() if re.match(r"\| [A-Z][A-Za-z0-9]*V2 \|",line)]
        expected=[]
        for name,spec in sorted(self.reg.items()):
            wire,_=r.maximum_wire_fixture(name,self.reg)
            expected.append("| "+" | ".join((name,spec.phase,spec.size_class,str(len(wire)),
                r.wire_digest(name,wire,self.reg)))+" |")
        self.assertEqual(actual,expected)

    def test_pristine_joint_arm_maxima_have_independent_counterexamples(self):
        import copy
        # These are hand-selected semantic arms built from fresh field-maximal
        # seeds.  They do not call the production rule applier or inspect its
        # selected arm, and therefore catch carry-over between arm candidates.
        token=self._independent_seed("AcquisitionTokenV2")
        token.update(ownerKind="process",ownerTrustAnchorSha256=None,
            resourceRole="authority-child:control-receive")
        reservation=self._independent_seed("AcquisitionReservationV2")
        reservation.update(ownerKind="process",expectedRole="authority-child:directory-fd",
            expectedKind="directory-fd")
        control=self._independent_seed("ControlEnvelopeV2")
        control.update(kind="service-validation",
            bodySchema="ServiceExecutionValidationReceiptV2")
        supervisor=self._independent_seed("SupervisorClosureBodyV2")
        supervisor.update(servicePredecessorKind="terminal-present",
            missingServiceTerminalReceiptSha256=None,serviceTerminalOutcome="uncertain",
            closureOutcome="uncertain")
        for item,role in zip(supervisor["guardianClosureRefs"],(
                "target-base-apk","framework","native-module-apk","original-pdf","mark")):
            item["fileRole"]=role
        independent={
            "AcquisitionReservationV2":reservation,
            "AcquisitionTokenV2":token,
            "ControlEnvelopeV2":control,
            "SupervisorClosureBodyV2":supervisor,
        }
        stale_limits={"AcquisitionReservationV2":687,"AcquisitionTokenV2":648,
            "ControlEnvelopeV2":731,"SupervisorClosureBodyV2":20508}
        for name,value in independent.items():
            raw=r.canonical(value)
            with self.subTest(schema=name):
                r.validate_body(name,raw,self.reg)
                produced=r.canonical(r.maximum_fixture(name,self.reg)[0])
                self.assertEqual(len(produced),len(raw))
                self.assertGreater(len(raw),stale_limits[name])

        body=r.canonical(supervisor)
        envelope=self._independent_seed("SupervisorClosureEnvelopeV2")
        envelope.update(bodySchema="SupervisorClosureBodyV2",bodyByteLength=len(body),
            bodySha256=r.wire_digest("SupervisorClosureBodyV2",body,self.reg))
        for field in ("planCoreSha256","executionBindingSha256"):
            envelope[field]=supervisor[field]
        wire=r.envelope_frame("SupervisorClosureEnvelopeV2",envelope,body,self.reg)
        produced,_=r.maximum_wire_fixture("SupervisorClosureEnvelopeV2",self.reg)
        self.assertEqual(len(produced),len(wire))
        self.assertGreater(len(wire),21256)

        # Swapping discriminator declaration order cannot change the maximum:
        # each arm must begin from a pristine seed, never the prior arm.
        def trap(name,arms):
            return r.schema(name,"S","SMALL",{"arm":r.Enum(*arms),
                "payload":r.Nullable(r.Text(128))},rules=(
                    r.Rule("mask",("arm",),("erase",(),("payload",))),))
        reg_a=r.compile_registry((trap("CarryTrapAV2",("erase","keep")),))
        reg_b=r.compile_registry((trap("CarryTrapBV2",("keep","erase")),))
        max_a=r.maximum_fixture("CarryTrapAV2",reg_a)[0]
        max_b=r.maximum_fixture("CarryTrapBV2",reg_b)[0]
        self.assertEqual((max_a["arm"],max_a["payload"] is not None),("keep",True))
        self.assertEqual((max_b["arm"],max_b["payload"] is not None),("keep",True))
        # Schema names have equal width, so the byte maxima must also agree.
        self.assertEqual(len(r.canonical(max_a)),len(r.canonical(max_b)))

    def test_every_field_missing_unknown_and_wrong_type(self):
        for name,spec in self.reg.items():
            original=self.values[name]
            with self.subTest(schema=name,field="unknown"),self.assertRaises(r.ContractError):
                r.validate_body(name,r.canonical(dict(original,unknownField=0)),self.reg)
            for key,member in spec.fields:
                value=original.copy();del value[key]
                with self.subTest(schema=name,field=key,mutation="missing"),self.assertRaises(r.ContractError):
                    r.validate_body(name,r.canonical(value),self.reg)
                value=original.copy()
                value[key]=[] if member.kind not in ("vector","tuple") else "wrong-type"
                with self.subTest(schema=name,field=key,mutation="type"),self.assertRaises(r.ContractError):
                    r.validate_body(name,r.canonical(value),self.reg)

    def test_cross_schema_retag_never_structurally_aliases(self):
        names=tuple(self.reg)
        for index,name in enumerate(names):
            raw=r.canonical(self.values[name])
            for target in (names[(index+1)%len(names)],names[(index+17)%len(names)]):
                with self.subTest(source=name,target=target),self.assertRaises(r.ContractError):
                    r.validate_body(target,raw,self.reg)

    def test_every_discriminated_null_arm_is_closed(self):
        import copy
        def make(member,path):
            if member.kind=="object": return r.maximum_fixture(member.args[0],self.reg)[0]
            if member.kind=="nullable": return make(member.args[0],path)
            if member.kind=="vector": return [make(member.args[0],path) for _ in range(member.args[1])]
            if member.kind=="tuple": return [make(x,path) for x in member.args]
            if member.kind=="choice": return r.maximum_fixture(member.args[0],self.reg)[0]
            return r._fixture_scalar(member,path,self.reg)
        for name,spec in self.reg.items():
            fields=dict(spec.fields)
            for rule in spec.rules:
                if rule.kind!="mask": continue
                tag,required,forbidden=rule.args
                value=copy.deepcopy(self.values[name]);value[rule.fields[0]]=tag
                # Preserve the arm under test when another closed dispatch
                # field determines this discriminator (for example an
                # acquisition resource role determines its closure proof).
                for dependency in spec.rules:
                    if dependency.kind=="dispatch-value" and dependency.fields[1]==rule.fields[0]:
                        sources=tuple(source for source,target in dependency.args if target==tag)
                        self.assertTrue(sources,(name,rule.fields[0],tag))
                        value[dependency.fields[0]]=sources[0]
                    elif dependency.kind=="nonnull-constant" and dependency.fields[0]==rule.fields[0]:
                        value[dependency.fields[1]]=dependency.args[0]
                r._fixture_apply_rules(spec,value,self.reg,make)
                with self.subTest(schema=name,arm=tag):
                    self.assertEqual(value[rule.fields[0]],tag)
                    r.validate_body(name,r.canonical(value),self.reg)
                for key in required+forbidden:
                    bad=copy.deepcopy(value)
                    bad[key]=None if key in required else make(fields[key].args[0],name+"/"+key)
                    with self.subTest(schema=name,arm=tag,field=key),self.assertRaises(r.ContractError):
                        r.validate_body(name,r.canonical(bad),self.reg)

    def test_acquisition_closure_arm_retains_selected_role_and_closed_state(self):
        import copy
        spec=self.reg["AcquisitionStateV2"]
        owners=("outer","verifier","supervisor","service","authority-child",
                "frida-child","guardian","callback")
        roles=("process","thread","job","signing-key","stream-key","payload-key",
            "ack-key","terminal-key","control-send","control-receive","data-send",
            "data-receive","file-fd","directory-fd","spool","store","gate","drain")
        kind_by_role={"process":"process","thread":"thread","job":"job",
            "signing-key":"key","stream-key":"key","payload-key":"key",
            "ack-key":"key","terminal-key":"key","control-send":"endpoint",
            "control-receive":"endpoint","data-send":"endpoint","data-receive":"endpoint",
            "file-fd":"fd","directory-fd":"directory-fd","spool":"spool",
            "store":"store","gate":"gate","drain":"drain"}
        proof_by_role={"process":"process-joined","thread":"thread-closed",
            "job":"job-empty-closed","signing-key":"key-destroyed",
            "stream-key":"key-destroyed","payload-key":"key-destroyed",
            "ack-key":"key-destroyed","terminal-key":"key-destroyed",
            "control-send":"endpoint-send-closed","control-receive":"endpoint-receive-eof-closed",
            "data-send":"endpoint-send-closed","data-receive":"endpoint-receive-eof-closed",
            "file-fd":"fd-closed","directory-fd":"directory-fd-closed",
            "spool":"spool-closed","store":"store-closed","gate":"gate-closed",
            "drain":"drain-closed"}
        expected_kind=tuple((owner+":"+role,kind_by_role[role])
                            for owner in owners for role in roles)
        expected_proof=tuple((owner+":"+role,proof_by_role[role])
                             for owner in owners for role in roles)
        self.assertEqual(len(expected_kind),144)
        self.assertEqual(r.RESOURCE_ROLE_KIND_TABLE,expected_kind)
        self.assertEqual(r.RESOURCE_ROLE_CLOSURE_TABLE,expected_proof)
        closure_masks={
            "process-joined":(("joinReceiptSha256",),("closeReceiptSha256","jobEmptyReceiptSha256","endpointEofReceiptSha256","keyDestructionReceiptSha256")),
            "job-empty-closed":(("closeReceiptSha256","jobEmptyReceiptSha256"),("joinReceiptSha256","endpointEofReceiptSha256","keyDestructionReceiptSha256")),
            "endpoint-send-closed":(("closeReceiptSha256",),("joinReceiptSha256","jobEmptyReceiptSha256","endpointEofReceiptSha256","keyDestructionReceiptSha256")),
            "endpoint-receive-eof-closed":(("closeReceiptSha256","endpointEofReceiptSha256"),("joinReceiptSha256","jobEmptyReceiptSha256","keyDestructionReceiptSha256")),
            "key-destroyed":(("keyDestructionReceiptSha256",),("closeReceiptSha256","joinReceiptSha256","jobEmptyReceiptSha256","endpointEofReceiptSha256")),
        }
        for proof in ("thread-closed","fd-closed","directory-fd-closed","spool-closed",
                      "store-closed","gate-closed","drain-closed"):
            closure_masks[proof]=(("closeReceiptSha256",),("joinReceiptSha256",
                "jobEmptyReceiptSha256","endpointEofReceiptSha256","keyDestructionReceiptSha256"))
        identity_by_kind={kind:"WindowsObjectIdentityV2" for kind in kind_by_role.values()}
        identity_by_kind["process"]="ProcessIdentityV2"
        all_receipts=("closeReceiptSha256","joinReceiptSha256","jobEmptyReceiptSha256",
                      "endpointEofReceiptSha256","keyDestructionReceiptSha256")
        for role,kind in expected_kind:
            proof=dict(expected_proof)[role]
            value=copy.deepcopy(self.values[spec.name])
            value.update(resourceRole=role,resourceKind=kind,closureProofKind=proof,
                state="created-closed",identitySchema=identity_by_kind[kind],
                identitySha256="11"*32,creationReceiptSha256="22"*32,
                firstUncertainty=None)
            for field in all_receipts: value[field]=None
            required,_forbidden=closure_masks[proof]
            for index,field in enumerate(required): value[field]=("%02x"%(48+index))*32
            with self.subTest(role=role,proof=proof):
                self.assertEqual(value["closureProofKind"],proof)
                self.assertEqual(value["state"],"created-closed")
                r.validate_body(spec.name,r.canonical(value),self.reg)
                with self.assertRaises(r.ContractError):
                    r.validate_body(spec.name,r.canonical(dict(value,state="created-uncertain")),self.reg)
                wrong=next(candidate for candidate in r.CLOSURE_PROOF_KINDS if candidate!=proof)
                with self.assertRaises(r.ContractError):
                    r.validate_body(spec.name,r.canonical(dict(value,closureProofKind=wrong)),self.reg)

        # The named-table compiler lock must reject even one plausible role
        # remapping rather than accepting a locally self-consistent mutation.
        changed=tuple((role,"thread-closed" if role=="verifier:process" else proof)
                      for role,proof in expected_proof)
        bad_rule=r.Rule("dispatch-value",("resourceRole","closureProofKind"),changed)
        bad_spec=replace(spec,rules=tuple(bad_rule if rule.kind=="dispatch-value" and
            rule.fields==("resourceRole","closureProofKind") else rule for rule in spec.rules))
        definitions=tuple(bad_spec if name==spec.name else candidate
                          for name,candidate in self.reg.items())
        with self.assertRaises(r.ContractError): r.compile_registry(definitions)

    def test_capability_result_bulk_vector_cardinality_is_closed_by_arm(self):
        import copy
        spec=self.reg["CapabilityResultRefV2"]
        def make(member,path):
            if member.kind=="nullable": return make(member.args[0],path)
            return r._fixture_scalar(member,path,self.reg)
        for arm in ("none","detached"):
            value=copy.deepcopy(self.values[spec.name]);value["kind"]=arm
            r._fixture_apply_rules(spec,value,self.reg,make)
            with self.subTest(arm=arm):
                self.assertEqual(value["bulkRefCount"],0)
                self.assertEqual(value["bulkRefDigests"],[])
                r.validate_body(spec.name,r.canonical(value),self.reg)
                bad=dict(value,bulkRefCount=1,bulkRefDigests=["ab"*32])
                with self.assertRaises(r.ContractError):
                    r.validate_body(spec.name,r.canonical(bad),self.reg)
        value=copy.deepcopy(self.values[spec.name]);value["kind"]="transcript-set"
        r._fixture_apply_rules(spec,value,self.reg,make)
        value.update(bulkRefCount=0,bulkRefDigests=[])
        with self.assertRaises(r.ContractError):
            r.validate_body(spec.name,r.canonical(value),self.reg)

    def test_detached_envelope_body_dispatch_is_uniquely_derived(self):
        import copy
        import hmac
        literal={
            "ControlEnvelopeV2":(
                ("bootstrap-validation",("BootstrapValidationReceiptV2",)),
                ("service-validation",("ServiceExecutionValidationReceiptV2",)),
                ("operation",("CapabilityOperationReceiptV2",)),
                ("barrier",("AuthorityBarrierAcceptanceV2",)),
                ("terminalization",("CapabilityTerminalizationEnvelopeV2",)),
                ("detached",("DetachedPayloadV2",)),
                ("bulk-reference",("DetachedBulkReferenceV2",))),
            "AckControlEnvelopeV2":(
                ("offer",("EndpointOfferV2",)),("accept",("EndpointAcceptV2",)),
                ("grant",("EndpointFirstWriteGrantV2",)),
                ("settlement",("SettlementAckEnvelopeV2",)),
                ("carrier-terminal",("InlineTerminalEnvelopeV2","BulkManifestEnvelopeV2")),
                ("close",("AckControlCloseBodyV2",))),
            "SnapshotTransportControlEnvelopeV2":(
                ("settlement",("SnapshotTransportSettlementV2",)),
                ("terminal",("SnapshotTransportTerminalV2",))),
        }
        fingerprints={
            "ControlEnvelopeV2":"a123697f04fe017554ba36581e9c06bac2465b00ff852cbc6f7d06ca7f393f5d",
            "AckControlEnvelopeV2":"2ec03fda827b07d250136469cb26851a4bc8810f7bdf87010c4e3a91101e6e72",
            "SnapshotTransportControlEnvelopeV2":"efc20b4dee9b93e5c8565b38a50770354bfac415ee8e071a1aef14fc2b55b5df",
        }
        for name,expected in literal.items():
            spec=self.reg[name]
            dispatches=tuple(rule for rule in spec.rules if rule.kind=="dispatch-schema-ref"
                and rule.fields==("kind","bodySchema","bodySha256"))
            self.assertEqual(len(dispatches),1)
            self.assertEqual(dispatches[0].args,expected)
            self.assertEqual(r._dispatch_rule_fingerprint(dispatches[0]),fingerprints[name])
            inverse={body:kind for kind,bodies in expected for body in bodies}
            body_schema=dict(spec.fields)["bodySchema"]
            declared=set(body_schema.args if body_schema.kind=="enum" else body_schema.args[:1])
            self.assertEqual(set(inverse),declared)
            for body_name,kind in inverse.items():
                value={"kind":next(iter(dict(expected))),"bodySchema":body_name,
                       "bodySha256":"ab"*32}
                r._bind_envelope_body_dispatch(spec,value,body_name)
                self.assertEqual(value["kind"],kind)

            original=dispatches[0]
            changed_args=list(expected)
            changed_args[0]=(changed_args[0][0],expected[-1][1])
            changed=r.Rule(original.kind,original.fields,tuple(changed_args))
            for rules in (tuple(rule for rule in spec.rules if rule!=original),
                    tuple(changed if rule==original else rule for rule in spec.rules),
                    spec.rules+(changed,)):
                bad=replace(spec,rules=rules)
                definitions=tuple(bad if candidate_name==name else candidate
                                  for candidate_name,candidate in self.reg.items())
                with self.subTest(schema=name,mutation=len(rules)),self.assertRaises(r.ContractError):
                    r.compile_registry(definitions)
            missing=replace(spec,rules=tuple(rule for rule in spec.rules if rule!=original))
            with self.assertRaises(r.ContractError):
                r._bind_envelope_body_dispatch(missing,{"kind":expected[0][0]},expected[0][1][0])
            with self.assertRaises(r.ContractError):
                r._bind_envelope_body_dispatch(spec,{"kind":expected[0][0]},"MissingBodyV2")

        def independent_ld(domain,parts):
            encoded=domain.encode("ascii")
            return (len(encoded).to_bytes(4,"big")+encoded+len(parts).to_bytes(4,"big")+
                    b"".join(len(part).to_bytes(8,"big")+part for part in parts))
        key=bytes(range(32));key_id="ab"*32
        for name,body_name,correct_kind,bad_kind in (
                ("AckControlEnvelopeV2","AckControlCloseBodyV2","close","offer"),
                ("SnapshotTransportControlEnvelopeV2","SnapshotTransportTerminalV2","terminal","settlement")):
            body,_=r.maximum_wire_fixture(body_name,self.reg)
            body_value,_=r.decode_wire(body_name,body,self.reg)
            metadata=copy.deepcopy(self.values[name])
            metadata.update(bodySchema=body_name,bodyByteLength=len(body),
                bodySha256=r.wire_digest(body_name,body,self.reg),keyId=key_id)
            r._bind_envelope_body_dispatch(self.reg[name],metadata,body_name)
            for field in ("constructionId","contextPhase","planCoreSha256","executionBindingSha256"):
                if field in metadata and field in body_value: metadata[field]=body_value[field]
            def remac(kind):
                value=copy.deepcopy(metadata);value["kind"]=kind
                def digest(field): return bytes.fromhex(value[field]) if value.get(field) is not None else b""
                if name=="AckControlEnvelopeV2":
                    parts=(digest("planCoreSha256"),digest("executionBindingSha256"),
                        digest("ackControlBindingSha256"),value["direction"].encode(),
                        value["sequenceClass"].encode(),value["messageSequence"].to_bytes(8,"big"),
                        digest("previousEnvelopeSha256"),kind.encode())
                else:
                    parts=(digest("constructionId"),value["contextPhase"].encode(),
                        digest("planCoreSha256"),digest("executionBindingSha256"),
                        digest("bindingSha256"),kind.encode())
                parts+=(key_id.encode("ascii"),digest("bodySha256"),len(body).to_bytes(8,"big"),body)
                value["tag"]=base64.b64encode(hmac.digest(key,
                    independent_ld(r.PREFIX+name+"/mac",parts),"sha256")).decode()
                raw=r.canonical(value)
                return len(raw).to_bytes(4,"big")+raw+len(body).to_bytes(8,"big")+body
            valid=remac(correct_kind)
            self.assertEqual(r.verify_envelope(name,valid,key,key_id,self.reg)["kind"],correct_kind)
            # The semantic mismatch is freshly MACed under the right key.  It
            # must still fail before authentication can bless the wrong body.
            with self.subTest(schema=name),self.assertRaises(r.ContractError):
                r.verify_envelope(name,remac(bad_kind),key,key_id,self.reg)

    def test_typed_reference_target_missing_duplicate_and_dag(self):
        leaf=r.schema("GraphLeafV2","S","SMALL",{"n":r.Integer(0,9)})
        alternate=r.schema("GraphOtherV2","S","SMALL",{"n":r.Integer(0,9)})
        parent=r.schema("GraphParentV2","S","SMALL",{"leaf":r.Ref("GraphLeafV2")})
        reg=r.compile_registry((leaf,alternate,parent))
        a=r.canonical({"authority":r.PREFIX+"schema/GraphLeafV2","schemaVersion":2,"n":1})
        other=r.canonical({"authority":r.PREFIX+"schema/GraphOtherV2","schemaVersion":2,"n":1})
        ah=r.wire_digest("GraphLeafV2",a,reg)
        b=r.canonical({"authority":r.PREFIX+"schema/GraphParentV2","schemaVersion":2,"leaf":ah})
        result=r.reference_graph((("GraphParentV2",b),("GraphLeafV2",a)),reg)
        self.assertEqual(result[0],ah)
        for records in ((("GraphParentV2",b),),(("GraphLeafV2",a),("GraphLeafV2",a))):
            with self.assertRaises(r.ContractError): r.reference_graph(records,reg)
        wrong=r.canonical({"authority":r.PREFIX+"schema/GraphParentV2","schemaVersion":2,
                           "leaf":r.wire_digest("GraphOtherV2",other,reg)})
        with self.assertRaises(r.ContractError):
            r.reference_graph((("GraphParentV2",wrong),("GraphOtherV2",other)),reg)

    def test_graph_dispatch_joins_resolve_actual_schema_recursively(self):
        """Fresh digests cannot turn a valid union member into the selected arm."""
        def obj(name,**fields):
            return {"authority":r.PREFIX+"schema/"+name,"schemaVersion":2,**fields}

        leaf_a=r.schema("GraphDispatchLeafAV2","S","SMALL",{"n":r.Integer(0,9)})
        leaf_b=r.schema("GraphDispatchLeafBV2","S","SMALL",{"n":r.Integer(0,9)})
        targets=("GraphDispatchLeafAV2","GraphDispatchLeafBV2")
        arms=(("a",("GraphDispatchLeafAV2",)),("b",("GraphDispatchLeafBV2",)))
        plain=r.schema("GraphDispatchRefV2","S","SMALL",{
            "kind":r.Enum("a","b"),"target":r.Ref(*targets)},rules=(
                r.Rule("dispatch-ref",("kind","target"),arms),))
        typed=r.schema("GraphDispatchSchemaRefV2","S","SMALL",{
            "kind":r.Enum("a","b"),"targetSchema":r.Enum(*targets),
            "target":r.Ref(*targets)},rules=(r.Rule("dispatch-schema-ref",
                ("kind","targetSchema","target"),arms),))
        outer=r.schema("GraphDispatchOuterV2","S","SMALL",{
            "plain":r.Object("GraphDispatchRefV2"),
            "typed":r.Object("GraphDispatchSchemaRefV2")})
        reg=r.compile_registry((leaf_a,leaf_b,plain,typed,outer))
        leaf_raw={name:r.canonical(obj(name,n=index)) for index,name in
                  enumerate(targets)}
        digest={name:r.wire_digest(name,leaf_raw[name],reg) for name in targets}
        records=tuple((name,leaf_raw[name]) for name in targets)

        def plain_raw(kind,target):
            return r.canonical(obj("GraphDispatchRefV2",kind=kind,target=target))
        def typed_raw(kind,declared,target):
            return r.canonical(obj("GraphDispatchSchemaRefV2",kind=kind,
                                   targetSchema=declared,target=target))
        valid_plain=plain_raw("a",digest[targets[0]])
        valid_typed=typed_raw("a",targets[0],digest[targets[0]])
        self.assertEqual(len(r.reference_graph(
            (("GraphDispatchRefV2",valid_plain),records[0]),reg)),2)
        self.assertEqual(len(r.reference_graph(
            (("GraphDispatchSchemaRefV2",valid_typed),records[0]),reg)),2)

        # Both wrong targets are valid members of the broad Ref union and all
        # records are freshly encoded and hashed.  Only the discriminator join
        # distinguishes them, so byte corruption or a stale hash cannot be the
        # reason for rejection.
        wrong_plain=plain_raw("a",digest[targets[1]])
        wrong_typed=typed_raw("a",targets[0],digest[targets[1]])
        r.validate_body("GraphDispatchRefV2",wrong_plain,reg)
        r.validate_body("GraphDispatchSchemaRefV2",wrong_typed,reg)
        for name,raw in (("GraphDispatchRefV2",wrong_plain),
                         ("GraphDispatchSchemaRefV2",wrong_typed)):
            with self.subTest(schema=name),self.assertRaises(r.ContractError):
                r.reference_graph(((name,raw),records[1]),reg)

        valid_outer=r.canonical(obj("GraphDispatchOuterV2",
            plain=obj("GraphDispatchRefV2",kind="a",target=digest[targets[0]]),
            typed=obj("GraphDispatchSchemaRefV2",kind="a",
                targetSchema=targets[0],target=digest[targets[0]])))
        self.assertEqual(len(r.reference_graph(
            (("GraphDispatchOuterV2",valid_outer),records[0]),reg)),2)
        for field,replacement in (
            ("plain",obj("GraphDispatchRefV2",kind="a",target=digest[targets[1]])),
            ("typed",obj("GraphDispatchSchemaRefV2",kind="a",
                targetSchema=targets[0],target=digest[targets[1]]))):
            outer_value=r.decode_canonical(valid_outer)
            outer_value[field]=replacement
            wrong_outer=r.canonical(outer_value)
            r.validate_body("GraphDispatchOuterV2",wrong_outer,reg)
            with self.subTest(inline=field),self.assertRaises(r.ContractError):
                # Include both valid union leaves.  The broad Ref scan is thus
                # fully satisfied and only recursive discriminator binding can
                # reject the selected-arm/actual-schema mismatch.
                r.reference_graph((("GraphDispatchOuterV2",wrong_outer),)+records,reg)

        # The nullable schema/ref pair is graph-closed too, even when this
        # internal helper is called on an already structurally decoded value.
        nullable=r.schema("GraphNullableDispatchV2","S","SMALL",{
            "kind":r.Enum("a","b"),"targetSchema":r.Nullable(r.Enum(*targets)),
            "target":r.Nullable(r.Ref(*targets))},rules=(
                r.Rule("dispatch-schema-ref",("kind","targetSchema","target"),arms),))
        nullable_reg=dict(reg);nullable_reg[nullable.name]=nullable
        with self.assertRaises(r.ContractError):
            r._validate_graph_bound_rules(nullable.name,obj(nullable.name,kind="a",
                targetSchema=targets[0],target=None),{},nullable_reg)

    def test_production_platform_observation_dispatch_is_graph_bound(self):
        """Literal seven-record production DAG reproduces the reviewed defect."""
        def obj(name,**fields):
            return {"authority":r.PREFIX+"schema/"+name,"schemaVersion":2,**fields}
        h=lambda label:hashlib.sha256(label.encode("ascii")).hexdigest()
        x=dict(contextPhase="pre-plan",constructionId=h("construction"),
               planCoreSha256=None,executionBindingSha256=None)

        trust=obj("TrustAnchorPinV2",algorithm="Ed25519",
            publicKey=base64.b64encode(bytes(32)).decode(),
            publicKeySha256=h("public-key"),policyVersion=1)
        trust_raw=r.canonical(trust)
        trust_sha=r.wire_digest("TrustAnchorPinV2",trust_raw,self.reg)
        token=obj("AcquisitionTokenV2",**x,ownerKind="provisioned-root",
            ownerIdentity=None,ownerTrustAnchorSha256=trust_sha,
            resourceRole="outer:process",acquisitionOrdinal=0,generation=h("generation"))
        token_raw=r.canonical(token)
        token_sha=r.wire_digest("AcquisitionTokenV2",token_raw,self.reg)
        reservation=obj("AcquisitionReservationV2",**x,
            ownerKind="provisioned-root",tokenSha256=token_sha,
            expectedKind="process",expectedRole="outer:process",ownerIdentity=None,
            absoluteDeadlineNs="100")
        reservation_raw=r.canonical(reservation)
        reservation_sha=r.wire_digest("AcquisitionReservationV2",reservation_raw,self.reg)
        authority=obj("AcquisitionAuthorityObservationV2",**x,
            reservationSha256=reservation_sha,tokenSha256=token_sha,
            observerKind="provisioned-root",observerIdentity=None,
            observerTrustAnchorSha256=trust_sha,observationNonce=h("observation"),
            capturedMonotonicNs="1",outcome="authorized")
        authority_raw=r.canonical(authority)
        authority_sha=r.wire_digest("AcquisitionAuthorityObservationV2",authority_raw,self.reg)
        process=obj("ProcessIdentityV2",platform="android",pid=1,
            processStartId="1",bootId=h("boot"),imageSha256=h("image"),
            acquisitionAuthorityObservationSha256=authority_sha)
        process_raw=r.canonical(process)
        process_sha=r.wire_digest("ProcessIdentityV2",process_raw,self.reg)
        stat=obj("FileStatV2",device="1",inode="2",mode="3",uid="4",gid="5",
            nlink="1",size="6",mtimeNs="7",ctimeNs="8",blocks="9",
            blockSize="4096",statSerializationVersion=2)
        stat_raw=r.canonical(stat)
        stat_sha=r.wire_digest("FileStatV2",stat_raw,self.reg)
        observation=obj("PlatformObservationV2",**x,operation="capture",
            ownerIdentity=process_sha,subjectSchema="FileStatV2",subjectSha256=stat_sha,
            operationId=h("operation"),observationOrdinal=0,
            previousObservationSha256=None,sourceImageSha256=h("source-image"),
            sourcePolicySha256=h("source-policy"),capturedHostNs="2",
            operationDeadlineNs="100",outcome="proved")
        observation_raw=r.canonical(observation)
        records=(("TrustAnchorPinV2",trust_raw),("AcquisitionTokenV2",token_raw),
            ("AcquisitionReservationV2",reservation_raw),
            ("AcquisitionAuthorityObservationV2",authority_raw),
            ("ProcessIdentityV2",process_raw),("FileStatV2",stat_raw),
            ("PlatformObservationV2",observation_raw))
        self.assertEqual(len(r.reference_graph(records,self.reg)),7)

        wrong=dict(observation,subjectSchema="JobMemberSetV2")
        wrong_raw=r.canonical(wrong)
        r.validate_body("PlatformObservationV2",wrong_raw,self.reg)
        wrong_records=records[:-1]+(("PlatformObservationV2",wrong_raw),)
        with self.assertRaises(r.ContractError):
            r.reference_graph(wrong_records,self.reg)

    def test_production_dispatch_graph_interactions(self):
        """All major production dispatcher families reject an in-union target."""
        import copy
        h="ab"*32
        cases=(
            ("AcquisitionResultV2",{"result":"acquired",
                "identitySchema":"ProcessIdentityV2","identitySha256":h},
                "ProcessIdentityV2","WindowsObjectIdentityV2"),
            ("AcquisitionStateV2",{"resourceKind":"process",
                "identitySchema":"ProcessIdentityV2","identitySha256":h},
                "ProcessIdentityV2","WindowsObjectIdentityV2"),
            ("TranscriptAdmissionBodyV2",{"carrier":"inline",
                "sourceCarrierTerminalEnvelopeSha256":h},
                "InlineTerminalEnvelopeV2","BulkManifestEnvelopeV2"),
            ("TranscriptRefV2",{"carrier":"inline",
                "sourceCarrierTerminalEnvelopeSha256":h},
                "InlineTerminalEnvelopeV2","BulkManifestEnvelopeV2"),
            ("ControlEnvelopeV2",{"kind":"bootstrap-validation",
                "bodySchema":"BootstrapValidationReceiptV2","bodySha256":h},
                "BootstrapValidationReceiptV2","ServiceExecutionValidationReceiptV2"),
            ("AckControlEnvelopeV2",{"kind":"close",
                "bodySchema":"AckControlCloseBodyV2","bodySha256":h},
                "AckControlCloseBodyV2","EndpointOfferV2"),
            ("SnapshotTransportControlEnvelopeV2",{"kind":"terminal",
                "bodySchema":"SnapshotTransportTerminalV2","bodySha256":h},
                "SnapshotTransportTerminalV2","SnapshotTransportSettlementV2"),
            ("GuardianControlBodyV2",{"kind":"close",
                "payloadSchema":"GuardianControlCloseV2","payloadSha256":h},
                "GuardianControlCloseV2","GuardianCancelV2"),
            ("ServiceGlobalRecordV2",{"recordKind":"cleanup-observation",
                "semanticBodySchema":"PlatformObservationV2","semanticBodySha256":h},
                "PlatformObservationV2","SuccessSealV2"),
            ("RequesterTerminalRegistryV2",{"winnerKind":"verifier-terminal",
                "winnerBodySchema":"RequesterTerminalBodyV2","winnerBodySha256":h},
                "RequesterTerminalBodyV2","VerifierCrashRequesterBodyV2"),
        )
        for name,updates,valid_target,wrong_target in cases:
            value=copy.deepcopy(self.values[name]);value.update(updates)
            # Inline AcquisitionState maxima carry their own identity join.
            # Supply that independently resolved schema when present so this
            # case isolates the top-level dispatcher under test.
            index={h:(valid_target,b"")}
            for child in value.values():
                if type(child) is dict and child.get("authority")==(
                        r.PREFIX+"schema/AcquisitionStateV2"):
                    index[child["identitySha256"]]=(child["identitySchema"],b"")
            with self.subTest(schema=name,control="valid"):
                r._validate_graph_bound_rules(name,value,index,self.reg)
            index[h]=(wrong_target,b"")
            with self.subTest(schema=name,attack=wrong_target),self.assertRaises(r.ContractError):
                r._validate_graph_bound_rules(name,value,index,self.reg)

    def test_supervisor_terminal_present_outcome_is_typed_graph_bound(self):
        import copy
        production=self.reg["SupervisorClosureBodyV2"]
        terminal_guard=r.Rule("not-constant-if",
            ("servicePredecessorKind","serviceTerminalOutcome"),
            ("terminal-present","missing"))
        relation=r.Rule("envelope-body-field-equal",
            ("serviceTerminalEnvelopeSha256","serviceTerminalOutcome"),
            ("ServiceTerminalEnvelopeV2","ServiceTerminalBodyV2","outcome"))
        self.assertIn(terminal_guard,production.rules)
        self.assertIn(relation,production.rules)
        for critical in (terminal_guard,relation):
            bad=replace(production,rules=tuple(rule for rule in production.rules if rule!=critical))
            definitions=tuple(bad if name==production.name else candidate
                              for name,candidate in self.reg.items())
            with self.subTest(removed=critical.kind),self.assertRaises(r.ContractError):
                r.compile_registry(definitions)
        value=copy.deepcopy(self.values[production.name])
        self.assertEqual(value["servicePredecessorKind"],"terminal-present")
        value["serviceTerminalOutcome"]="missing"
        with self.assertRaises(r.ContractError):
            r.validate_body(production.name,r.canonical(value),self.reg)

        service_wire,_=r.maximum_wire_fixture("ServiceTerminalEnvelopeV2",self.reg)
        service_metadata,service_body_raw=r.decode_wire("ServiceTerminalEnvelopeV2",
            service_wire,self.reg)
        service_body,_=r.decode_wire("ServiceTerminalBodyV2",service_body_raw,self.reg)
        service_digest=r.wire_digest("ServiceTerminalEnvelopeV2",service_wire,self.reg)
        exact=copy.deepcopy(self.values[production.name])
        exact.update(servicePredecessorKind="terminal-present",
            serviceTerminalEnvelopeSha256=service_digest,
            missingServiceTerminalReceiptSha256=None,
            serviceTerminalOutcome=service_body["outcome"])
        identity=exact["guardianClosureRefs"][0]["guardianAcquisitionState"]
        index={service_digest:("ServiceTerminalEnvelopeV2",service_wire),
               identity["identitySha256"]:(identity["identitySchema"],b"")}
        r._validate_graph_bound_rules(production.name,exact,index,self.reg)
        different=next(outcome for outcome in ("success","failure","uncertain")
                       if outcome!=service_body["outcome"])
        with self.assertRaises(r.ContractError):
            r._validate_graph_bound_rules(production.name,
                dict(exact,serviceTerminalOutcome=different),index,self.reg)

        # A small independently constructed DAG exercises the same typed
        # envelope/body join without relying on production fixture hashes.
        service_body=r.schema("GraphServiceTerminalBodyV2","S","SMALL",{
            "outcome":r.Enum("success","failure","uncertain")})
        service_envelope=r.schema("GraphServiceTerminalEnvelopeV2","S","SMALL",{
            "bodySchema":r.Const("GraphServiceTerminalBodyV2"),
            "bodyByteLength":r.Integer(1,4096),
            "bodySha256":r.Ref("GraphServiceTerminalBodyV2")},
            envelope_bodies=("GraphServiceTerminalBodyV2",),
            purposes=("envelope-hash",))
        supervisor=r.schema("GraphSupervisorClosureV2","S","SMALL",{
            "serviceTerminalEnvelopeSha256":r.Ref("GraphServiceTerminalEnvelopeV2"),
            "serviceTerminalOutcome":r.Enum("success","failure","uncertain")},
            rules=(r.Rule("envelope-body-field-equal",
                ("serviceTerminalEnvelopeSha256","serviceTerminalOutcome"),
                ("GraphServiceTerminalEnvelopeV2","GraphServiceTerminalBodyV2","outcome")),))
        reg=dict(self.reg)
        reg.update({item.name:item for item in (service_body,service_envelope,supervisor)})
        def obj(name,**fields):
            return {"authority":r.PREFIX+"schema/"+name,"schemaVersion":2,**fields}
        def graph_for(body_outcome,parent_outcome):
            body_raw=r.canonical(obj("GraphServiceTerminalBodyV2",outcome=body_outcome))
            body_sha=r.wire_digest("GraphServiceTerminalBodyV2",body_raw,reg)
            envelope_value=obj("GraphServiceTerminalEnvelopeV2",
                bodySchema="GraphServiceTerminalBodyV2",bodyByteLength=len(body_raw),
                bodySha256=body_sha)
            envelope_raw=r.envelope_frame("GraphServiceTerminalEnvelopeV2",
                envelope_value,body_raw,reg)
            envelope_sha=r.wire_digest("GraphServiceTerminalEnvelopeV2",envelope_raw,reg)
            parent_raw=r.canonical(obj("GraphSupervisorClosureV2",
                serviceTerminalEnvelopeSha256=envelope_sha,
                serviceTerminalOutcome=parent_outcome))
            return (("GraphSupervisorClosureV2",parent_raw),
                    ("GraphServiceTerminalEnvelopeV2",envelope_raw),
                    ("GraphServiceTerminalBodyV2",body_raw))
        graph=r.reference_graph(graph_for("success","success"),reg)
        self.assertEqual(len(graph),3)
        # Every digest and embedded body is freshly rebuilt; only the semantic
        # outcome join is wrong, so this is not a stale-hash negative.
        with self.assertRaises(r.ContractError):
            r.reference_graph(graph_for("failure","success"),reg)

    def test_closed_named_envelope_key_body_policy(self):
        original=self.reg["SupervisorClosureEnvelopeV2"]
        for change in ({"key_role":"service-E"},{"signature_profile":"ed25519-P"},
                       {"envelope_bodies":("ServiceTerminalBodyV2",)}):
            values=tuple(replace(spec,**change) if name==original.name else spec
                         for name,spec in self.reg.items())
            with self.subTest(change=change),self.assertRaises(r.ContractError):
                r.compile_registry(values)

    def test_all_signed_and_mac_envelopes_roundtrip_and_mutations(self):
        import hmac
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        signer=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public=signer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        kid="ab"*32
        for name,spec in self.reg.items():
            if not spec.envelope_bodies: continue
            raw,_=r.maximum_wire_fixture(name,self.reg)
            value,body=r.decode_wire(name,raw,self.reg)
            field=next(x for x in ("signingKeyId","supervisorSigningKeyId","keyId") if x in value)
            value[field]=kid
            message=r.authentication_input(name,r.canonical(value),body,self.reg)
            if spec.signature_profile.startswith("ed25519"):
                key=public;value["signature"]=base64.b64encode(signer.sign(message)).decode()
            else:
                key=bytes(range(32));value["tag"]=base64.b64encode(hmac.digest(key,message,"sha256")).decode()
            signed=r.envelope_frame(name,value,body,self.reg)
            with self.subTest(schema=name):
                self.assertEqual(r.verify_envelope(name,signed,key,kid,self.reg),value)
                with self.assertRaises(r.ContractError):
                    r.verify_envelope(name,signed,key,"cd"*32,self.reg)
                with self.assertRaises(r.ContractError):
                    r.verify_envelope(name,signed+b"x",key,kid,self.reg)
                bad=bytearray(signed);bad[-1]^=1
                with self.assertRaises(r.ContractError):
                    r.verify_envelope(name,bytes(bad),key,kid,self.reg)
                with self.assertRaises(r.ContractError):
                    r.verify_envelope(name,signed,bytes(32),kid,self.reg)

    def test_x25519_strict_coordinate_and_all_low_order_inputs(self):
        expected="9663aa1da97e848a914a436d04163dfbb89178f107f1b5b77ed3854203382854"
        peer=bytes.fromhex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254")
        self.assertEqual(r.checked_x25519(bytes(range(32)),peer).hex(),expected)
        for value in r.LOW_ORDER_X25519:
            with self.subTest(public=value),self.assertRaisesRegex(r.ContractError,"invalid-provenance"):
                r.checked_x25519(bytes(range(32)),bytes.fromhex(value))
        for peer in (b"",bytes(31),bytes(33),b"\xff"*32):
            with self.assertRaises(r.ContractError): r.checked_x25519(bytes(range(32)),peer)

    def test_snapshot_frame_exact_payload_header_key_and_bounds(self):
        key=bytes(range(32));name="SnapshotTransportChunkV2"
        for size in (1,65536):
            payload=b"x"*size;header=self.values[name].copy()
            header.update(chunkOrdinal=0,offset=0,chunkByteLength=size,
                          chunkSha256=hashlib.sha256(payload).hexdigest())
            raw=r.canonical(header);frame=r.snapshot_chunk_frame(raw,payload,key,self.reg)
            self.assertEqual(r.verify_snapshot_chunk(frame,key,raw,self.reg),payload)
            for bad in (frame[:-1],frame+b"x",frame[:-1]+bytes([frame[-1]^1])):
                with self.assertRaises(r.ContractError): r.verify_snapshot_chunk(bad,key,raw,self.reg)
            with self.assertRaises(r.ContractError): r.verify_snapshot_chunk(frame,bytes(32),raw,self.reg)
            for field,replacement in (("chunkOrdinal",1),("offset",1),("bindingSha256","ab"*32),
                    ("previousRecordSha256","cd"*32),("originalDeadlineNs","1"),
                    ("directionKeyId","ef"*32)):
                changed=r.canonical(dict(header,**{field:replacement}))
                with self.subTest(field=field),self.assertRaises(r.ContractError):
                    r.verify_snapshot_chunk(frame,key,changed,self.reg)
        for payload in (b"",b"x"*65537):
            with self.assertRaises(r.ContractError): r.snapshot_chunk_frame(raw,payload,key,self.reg)

    def test_literal_signed_schema_known_answers(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        def h(n): return ("%02x"%n)*32
        def body(name,**fields):
            return {"authority":r.PREFIX+"schema/"+name,"schemaVersion":2,**fields}
        context=dict(planCoreSha256=h(0),executionBindingSha256=h(1))
        common=dict(**context,authorityLaneBodySha256=h(2),guardianSessionId=h(7),
            childSessionId=h(6),fileRole="original-pdf",phase="before",readEpoch=0,
            fdAcquisitionReceiptSha256=h(10),keyId=h(11),workGateSha256=h(12),
            supervisorObservedNs="1000",operationDeadlineNs="1000000")
        public=base64.b64encode(bytes.fromhex(
            "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f")).decode()
        child=body("ChildStreamKeyAttestationBodyV2",**common,childProcessIdentity=h(4),
            childImageManifestSha256=h(5),guardianProcessAttestationSha256=h(8),
            guardianChallenge=h(9),childStreamPublicKey=public)
        guardian=body("GuardianStreamKeyAttestationBodyV2",**common,
            guardianProcessIdentity=h(4),guardianImageManifestSha256=h(5),
            childProcessIdentity=h(8),childChallenge=h(9),guardianStreamPublicKey=public)
        logical=body("LogicalAttachBindingV2",**context,fridaLaneBodySha256=h(2),
            serial="fixture-serial",package="fixture.package",component="fixture.package/.DocumentActivity",
            pid=3141,processStartId="9000001",uid=10100,fridaServerSessionId=h(6),
            observerSourceSha256=h(5),targetPolicySha256=h(8),logicalAttachNonce=h(9),
            physicalAttachReceiptSha256=h(10),freshSelectorAttestationSha256=h(11),
            selectorChallenge=h(12),physicalOperationId=h(13),loadOperationId=h(14),
            loadSourceByteLength=7,loadSourceSha256=h(15),stepCursorBeforeLoad=2,
            previousPhysicalStepReceiptSha256=h(16),supervisorObservedNs="1000",operationDeadlineNs="1000000")
        def failure(phase):
            return body("FirstFailureV2",contextPhase=phase,constructionId=h(3),
                planCoreSha256=None if phase=="pre-plan" else h(0),executionBindingSha256=None,
                layer="construction",state="CORE" if phase=="pre-plan" else "EXECUTION_BODY",
                operation=None,cursor=0 if phase=="pre-plan" else 9,code="internal-invariant",
                evidenceSchema=None,evidenceSha256=None,observedHostNs="1000",retryable=False)
        def snapshot(phase):
            fields=dict(contextPhase=phase,constructionId=h(3),
                planCoreSha256=None if phase=="pre-plan" else h(0),executionBindingSha256=None,
                ownerIdentitySha256=h(4),sourceLedgerPrefixSha256=h(5),stateCount=0)
            raw=r.canonical(body("AcquisitionSnapshotBodyV2",**fields,states=[]))
            return body("AcquisitionSnapshotRefV2",**fields,snapshotByteLength=len(raw),
                snapshotSha256=r.body_digest("AcquisitionSnapshotBodyV2",raw,self.reg))
        construction=body("ConstructionSettlementBodyV2",planCoreSha256=h(0),constructionId=h(3),
            constructionCursor="EXECUTION_BODY",executionState="not-built",
            candidateExecutionBodySha256=None,candidateExecutionAttestationSha256=None,
            acquisitionSnapshotRef=snapshot("pre-E"),firstFailure=failure("pre-E"),
            outerOwnerIdentity=h(4),outerCheckpointSha256=h(5),settlementDeadlineNs="1000000",
            observedNs="1000",outcome="settled-abort")
        preplan=body("PrePlanAbortBodyV2",constructionId=h(3),outerOwnerIdentity=h(4),
            outerImageSha256=h(5),constructionCursor="CORE",acquisitionSnapshotRef=snapshot("pre-plan"),
            firstFailure=failure("pre-plan"),settlementDeadlineNs="1000000",observedNs="1000",
            prePlanCleanupExpiryEnvelopeSha256=None,outcome="settled-abort")
        rows=(
            ("ChildStreamKeyAttestationEnvelopeV2",child,1363,
             "9e88f7e8b55af730147875c7c578380026372a2dbfd49b965ef7eff5c379336d",
             "d01071fb2b8888ed6ea33c04058dd69574b1bf750217cd684b76c151f48b06ec",
             "6f21ad2dc0f1e0de689fa65f57a5e5f9fdfecdc8f7059ef6a13d662b766accf08a7f6e72bd9c68701be283e3b1d4a33b3dcaff8358cb093bf5a8e46b290d8e00"),
            ("LogicalAttachBindingEnvelopeV2",logical,1629,
             "af1bc1da1aada744482bf231f81fd3693ed12979230b477dbef5baa93866a516",
             "d9f4a3bf57403d70d51cb64be90eff74e00a8cf5d1871ed03e23fa5d9e0a3dfd",
             "d6ad67aff077584ef0170d3565ba8260fc5cb7835df454405b4052fe5dd6845d86784617c022d61867a90ae98aa3026369fe6a5d82b4b8a01113465b5b539d0e"),
            ("GuardianStreamKeyAttestationEnvelopeV2",guardian,1360,
             "7e8fa18b5ad97fcd78a677daaaf7a1eb886e049edfd91579be573b5139ecfa4d",
             "e44bcc1ed4ea7557e7c5f437e19f34c7420111ba5db014bb2b3ab7d5ae79ca91",
             "7e50ac187ac5cb054aabb228f49fdc804ae2c3d1c17eb90eb9e15f904a348f9137b1f39db3e77644879e098c4a95e61b06fa6cfb75e0f18195f59429dab17a09"),
            ("ConstructionSettlementEnvelopeV2",construction,1844,
             "8960fbab4b018a90564e040314e6b2eb524233d3959ef9b721cb1cf4d648d160",
             "6b57a29170245e538e911132c19ae7805dfc1d5a06fb28e2884f573232517186",
             "1451679255891123ec5ebfbaedcf9c7882e5bf0e6de83ef039a23b7516355ce40c2891e1da5f0fbcdbe7b631b0ec361cbff937152a624b65e579564779c6a203"),
            ("PrePlanAbortEnvelopeV2",preplan,1541,
             "0cc3d6cb1b58c6e96ac0e50450451432dc7720be83c347d5516ed05669e9cd27",
             "9dfb817c58eeec4751ae3c081634334ad3c0477262ee236ff9a0f1472e10a6cf",
             "2585f0f1eb06537846925fb12424c925d192044a9c8c98763e90173e341711e4de4cf2957122e6a16fdc7f847cd8fb1f01fe75d266eaffe6f46e65e95ebf550f"))
        signer=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        for name,value,length,digest,input_hash,signature in rows:
            with self.subTest(schema=name):
                target=value["authority"].removeprefix(r.PREFIX+"schema/");raw=r.canonical(value)
                self.assertEqual(len(raw),length);self.assertEqual(r.body_digest(target,raw,self.reg),digest)
                metadata=self.values[name].copy()
                metadata.update(bodySchema=target,bodyByteLength=len(raw),bodySha256=digest,signingKeyId="ab"*32)
                for field in ("planCoreSha256","executionBindingSha256","constructionId"):
                    if field in metadata: metadata[field]=value[field]
                preimage=r.authentication_input(name,r.canonical(metadata),raw,self.reg)
                self.assertEqual(hashlib.sha256(preimage).hexdigest(),input_hash)
                self.assertEqual(signer.sign(preimage).hex(),signature)

    def test_service_six_parts_and_execution_duplicate_E_are_literal(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        def independent_ld(domain,parts):
            d=domain.encode("ascii")
            return (len(d).to_bytes(4,"big")+d+len(parts).to_bytes(4,"big")+
                    b"".join(len(p).to_bytes(8,"big")+p for p in parts))
        raw=bytes.fromhex("7b2261223a225c225c5c5c7530303061c3a92f222c22617574686f72697479223a2272746c2d7265616465722f6e61746976652d706167652f616461707465722d76322f736368656d612f436f646563466978747572655632222c226e223a302c22736368656d6156657273696f6e223a322c227a223a66616c73657d")
        parts=(bytes(32),bytes([1])*32,b"ab"*32,
               bytes.fromhex("d12219cf9cdd2b3f84cc4e9c6bf57c0b7553c5ffe928d6acad68653f0c0a5f93"),
               (125).to_bytes(8,"big"),raw)
        message=independent_ld(r.PREFIX+"ServiceTerminalEnvelopeV2/signature",parts)
        self.assertEqual(hashlib.sha256(message).hexdigest(),
            "3820db3570c74dffb95c0cbf019bf1656d868de44b83a089755a6344d07b1667")
        self.assertEqual(Ed25519PrivateKey.from_private_bytes(bytes(range(32))).sign(message).hex(),
            "75d39fe8fe7d33cdd54ce75aee539546a0011bb38e2da8dcdb695320bd8cc21947176c85f522aa837a4319c5bdd93ad51d4f9b05ac4a6b5f1d40a39f73037705")
        for name in ("ServiceTerminalEnvelopeV2","ExecutionAttestationEnvelopeV2"):
            wire,_=r.maximum_wire_fixture(name,self.reg);value,body=r.decode_wire(name,wire,self.reg)
            p=bytes.fromhex(value["planCoreSha256"]);e=bytes.fromhex(value["executionBindingSha256"])
            h=bytes.fromhex(value["bodySha256"]);kid=value["signingKeyId"].encode("ascii")
            expected=independent_ld(r.PREFIX+name+"/signature",(p,e,kid,h,len(body).to_bytes(8,"big"),body))
            self.assertEqual(r.authentication_input(name,r.canonical(value),body,self.reg),expected)
            if name=="ExecutionAttestationEnvelopeV2": self.assertEqual(e,h)
            for changed in ((p,kid,h,len(body).to_bytes(8,"big"),body),
                    (p,e,h,kid,len(body).to_bytes(8,"big"),body)):
                self.assertNotEqual(expected,independent_ld(r.PREFIX+name+"/signature",changed))

    def test_expiry_phase_and_durable_reservation_are_closed(self):
        name="CleanupExpiryReceiptV2";value=self.values[name].copy()
        value.update(contextPhase="pre-plan",planCoreSha256=None,executionBindingSha256=None)
        with self.assertRaises(r.ContractError): r.validate_body(name,r.canonical(value),self.reg)
        value.update(contextPhase="pre-E",planCoreSha256="ab"*32)
        r.validate_body(name,r.canonical(value),self.reg)
        name="PublicationUncertainReceiptV2";value=self.values[name].copy()
        for field in ("reservedSlotId","publicationReservationSha256","lastDurableCheckpointSha256"):
            with self.subTest(field=field),self.assertRaises(r.ContractError):
                r.validate_body(name,r.canonical(dict(value,**{field:None})),self.reg)
        self.assertTrue(r.domain("CapabilityTerminalizationRequestV2","genesis",self.reg))
        self.assertEqual(self.reg["CapabilityTerminalizationEnvelopeV2"].key_role,"lane-terminalization")


if __name__ == "__main__":
    unittest.main(verbosity=2)
