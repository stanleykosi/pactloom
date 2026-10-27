"""Private unbound scaffold wiring; never activate or execute native artifacts."""
import hashlib,json,pathlib,unittest
from test_setup import L,TRUSTED
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
# Source-only P93 current-to-P92 legacy projection. This is not a runtime
# mode conversion or old qualification result. Every current byte is pinned
# before zero-based half-open spans restore the exact reviewed old bytes.
# Derived from reviewed shared-profile-exact-inverse-v2.json SHA256
# 16c22072aca8cb82bcdf0960aca96cfba177a0f1a8bacb8c81b54bcc46428bec.
CURRENT_DURABLE_PROFILE_INVERSES={
 'scripts/ci-financial-artifacts.py':('68a2c6023a631e1e62ad48cee887dd864a388b95dd08e052dcad87a5247f8166','f31041a577f3fa0dc65f5880ac0a77d8fd145e53d4d576524ede3e2adbec29ce',(
  (9,10,'786ac52e942c0dd6126225bf477e4536f68ec6c7ddb2aac0f289a96b5b1c90fc',b''),
  (56,74,'00a5a8bde6af21ae61ed37765d139c813e85a95b243d82d9af679bbbd10e4d55',b''),
  (75,76,'9d333a4c90de1b3976d6abd7a5dad0e40bf5e012a46c0f85fd851569a3b1460d',b''),
  (138,139,'4c36693895b85b4b98057dcc640c5a8593ca0bee7409c3829f61c5b1fda5990b',b"    need(type(value['version']) is int and value['version'] == MANIFEST_VERSION, 'version')\n"),
  (143,144,'76976495a6dc94d29a49340c7077674d22ec428df3808641f934fa171fc9e580',b"    need(type(value['files']) is dict and set(value['files']) == set(NAMES), 'file_set')\n"),
  (157,161,'81e157653ec767e1350eff61d1952e7940f36d4293bdf8c8b58c636ec2b0935c',b"    need({p.name for p in artifacts.iterdir()} == set(NAMES), 'file_set')\n    value = dict(version=MANIFEST_VERSION, identity=identity(producer), closure=closure(inputs), recipe=recipe(profile),\n                 files={name: file_pin(artifacts / name) for name in NAMES})\n"),
  (168,169,'f3ed56b2ac1c641b6e8b1fc1547effd945fff9f166d42864289e588c0396ec33',b'            for name in NAMES:\n'),
  (188,189,'17402beefbb88c073c6d4e805ed8d19ed327b00e3f190bbf49d3f6edfd4904a6',b"        for index, name in enumerate(('manifest.json', *NAMES)):\n"),
 )),
 'scripts/ci-financial-container.py':('a32958eccd9b77879b245e8dcad4520dc2782fa44093918b50ffaa22e96b35c8','3b030ae61e24b7d8d36a4a32cb1c71d3c88fa2c43fa90420a66cce663fa11be2',(
  (75,77,'92e64d88ea286fcd9f397ab3877acc27a64cf58a38e50894e1059a8dcae7ee3b',b''),
  (120,124,'4c9c6c117e0e639f2a7e359c9b372a564a948cad928b6e4da3e817279659252d',b"    C.require(manifest['schema']==1 and manifest['profile'] in (C.EXTERNAL_PROFILE,C.SEMANTIC_PROFILE) and\n"),
  (125,126,'4648381121a0ce890e1b2244a42191af869ce3b31587dc3a1699d2323861deb8',b"              set(manifest['files'])==set(RUNTIME_FILES+ARTIFACTS),'contract')\n"),
  (129,131,'8c96b7b0d961061f89c869554d0a8f37c181f5750962f6dd41406e00af6b4fd3',b"        mode=0o555 if name in ARTIFACTS else 0o444\n        raw,meta=secure_file(ROOT/name,UID if name=='pristine-setup' else 0,mode,512*1024*1024)\n"),
  (140,146,'98f0247927a88c7fe71aa30b0f794e0834a3c336da84dd082720b2b5a9a5b72a',b"    meta,digest=observed\n    pin={'schema_version':1,'profile':'financial-coordinator-common-image-linux-v1',\n         'executable_device':meta.st_dev,'executable_inode':meta.st_ino,\n         'executable_size':meta.st_size,'executable_sha256':digest}\n    write_new(pathlib.Path('/etc/wholepact/financial-coordinator-common-image-v1.json'),json.dumps(pin).encode(),0o444)\n"),
  (445,446,'df5f52d887e241d6cce72af0a62d57bc51b7adc45930874d486e9125b94af6b6',b"    C.require(not sys.argv[1:],'contract')\n"),
  (450,461,'91393d8032025cbac1fe50bf9b64beef53828662cb63399a17465303946ead85',b'        base,expected_profile=root_setup();parent=FixtureParent(original)\n'),
  (478,483,'6dac527f67f0f675f6bff72ad324b54cce734a3a135a4807ee191db7bea11b37',b''),
  (504,505,'6f71519dc75f5d522e36108ae5a52b0fe10b7868a0b3a7b17b336b525e30b4ed',b"if __name__=='__main__':main()\n"),
 )),
 'scripts/ci-financial-image.py':('c3182cc0b98d10cb252d3ab9b9e9e8e8e987766dcd732f8874fa3eea977bfb57','3609f2a672bd6db7e5f9edaa708877f11cff70e39be28644df0b3b50030b4633',(
  (26,27,'a101664593d521d5a81779f73a0d78cba871b2067319a0e0a36078fe43896d2a',b''),
  (38,43,'1613eef22384c931206b29e90f252b529f29e5ac7b51f4021941f694ae8d7a94',b''),
  (45,46,'114a1f249e624d65a6f831f0e7d1ba12a622ad14109c4511a528e5a91a3c956e',b''),
  (52,53,'05827254156b83f30a952fdf329b8bc01b8d20f72d007c87a2427ca480e55c32',b''),
  (61,62,'990f5a81253aa7177e4fabcf0bf223da0f457b7ebdbbc12a5232d5f9f3fd633b',b"    B._require(set(pins)==set(runtime_files())|set(ARTIFACT_FILES)|{MODULE_SOURCE},'input_allowlist')\n"),
  (84,87,'3ca17be17f7d01000008864ef26b3c0683e7663f8977b67921c8ad22ff511737',b''),
  (133,134,'b771717c78b4ab254d5233799dc3dab8abccc00df90ffca484e491814fe24e1c',b'    artifacts=\'\\n\'.join(f\'COPY --chown={"10001:10001" if n=="pristine-setup" else "0:0"} --chmod=0555 artifacts/{n} {IMAGE_ROOT}/{n}\' for n in ARTIFACT_FILES)\n'),
  (157,158,'dc985c742c2632aa8765c734a83667c65b4762279903dd3675b5678d06903a6e',b"    B._require(set(artifacts)==set(ARTIFACT_FILES),'input_allowlist')\n"),
  (169,170,'be5bade6986b6461c8b6a7f255e8cf6961b4dcdb6c15d8a26b68d164e726e383',b'    for name,path in [(n,ROOT/n) for n in (*runtime_files(),MODULE_SOURCE)]+[(n,pathlib.Path(artifacts[n])) for n in ARTIFACT_FILES]:\n'),
  (173,174,'05bed14bc873f63f13be033efed32db2572bfacd845fd73db8815ff5abe3a42b',b"        B._write_file(target/('artifacts' if name in ARTIFACT_FILES else 'inputs')/name,raw)\n"),
  (180,181,'7d39529568a9ca37e195aa1c1f6958210b81e84e16fcdf7f5bffa017ab1eb5d8',b"    allowed+=['inputs/'+n for n in (*runtime_files(),MODULE_SOURCE)]+['artifacts/'+n for n in ARTIFACT_FILES]\n"),
  (189,190,'2e0779746003ee2614dec225d62d4ebf2325886ecdfbbde9f58a60318cf63922',b"    for name in ARTIFACT_FILES:parser.add_argument('--'+name,required=True)\n"),
  (191,192,'28b1d52a529b237fe18d9c4227013bb1a1337a8855d07da8c20a42ec72590e58',b"    build_context(args.output,args.source_commit,{name:getattr(args,name.replace('-','_')) for name in ARTIFACT_FILES})\n"),
 )),
 'scripts/ci-financial-supervisor.py':('3e37d95a2bb9112f5af6814661535e16f075122aa2aaca801ea4141f84315014','1fd28d86df843d9ebf46bf159b9cb8c1a2b0487d8a94f174d599b935b545c389',(
  (40,41,'5e23a9df77a752815bab3a183f42ab0965fc7f52c5397e58e619cccb24e74d35',b''),
  (46,55,'e56063c4f9b18e74bdd7ed1846b1bac96755b1a06840b88e121e997233568eb0',b''),
  (270,271,'4fa2672e42213ddedbe13949efe0e95c55626d10e331b16c08014a46d651ec25',b"    require((HERE / 'qualification-gate-mode').read_bytes() in (b'financial-ui\\n',b'financial-semantic\\n'), 'source', 'gate_mode')\n"),
  (281,282,'de7a05944b1c0c57c153e905986df0c07779f4aa39d45e8c8fa07f20af15c27b',b''),
  (385,386,'07122c3dcebfb4baa19700094ef81cd27dcb055b948b71b22533fcfc07bffacc',b'def select_artifact(raw, name, target):\n'),
  (387,391,'3251837f0c6625cfd1c03ad14ce9916f5dbaf8c779922b02186ba2e9474cb2f3',b"    setup = name == 'pristine-setup'\n"),
  (408,410,'4edce06f266e301309b0539b32ee6e2aa8f75a49c775e55b78105700797af877',b"        require(row.get('features') == FEATURES[name], 'compile', 'artifact_features')\n"),
  (460,467,'caeb568e5753b475d1e8d38a27a1364a6bec8cedde38b95096b6118ae9c79b7d',b'def build_recipe(name):\n'),
  (480,481,'90f1bf63e8084318683a5bbfdad6221156becf9f9d10ace6146ec54e89193c62',b"    require(name in FEATURES and profile in (A.PIXEL_PROFILE,A.SEMANTIC_PROFILE), 'compile','artifact_profile')\n"),
  (497,498,'90f1bf63e8084318683a5bbfdad6221156becf9f9d10ace6146ec54e89193c62',b"    require(name in FEATURES and profile in (A.PIXEL_PROFILE,A.SEMANTIC_PROFILE), 'compile','artifact_profile')\n"),
  (549,552,'c5306f0b9c4b12555e2324aae04b8698a54bf1fc80f55fd6cd0ca6f13610b698',b"    require(A.RECIPE['rustc'] == B.RUSTC and A.RECIPE['coordinator_features'] == FEATURE\n            and A.RECIPE['artifact_features'] == FEATURES,\n"),
  (611,612,'7d2da5ee71f24fe9fee87c426930b5b6f3393494a2c5cca4dece484701960139',b'            artifacts=list(A.NAMES), pre_credential=True, reused=False, uploaded=False))\n'),
  (633,636,'6b22c58a4b9db84d37e35398afcf393e29f9223a81e8fd74f893f59e4784cb40',b"    for name in I.ARTIFACT_FILES:\n        exact_source(sha);selected=select_build_environment(env,name,I.profile());setup=name=='pristine-setup'\n        args=build_recipe(name)\n"),
  (638,642,'6e6c32d5d383b9923aeb902c2514aab524c1c0c94d4c2b80e6c4ca0efe986131',b"        artifact=select_artifact(raw,name,root/'target')\n"),
  (644,658,'e8c386448d942ff8869baf814e70614a091088f123428255e19f76eb6e867326',b"            listing=build_command(name,[str(inputs/name),'--list','--exact',LIVE_FIXTURE_TEST],\n                'compile',selected,seconds=30,limit=4096)\n            require(listing.decode('utf-8').splitlines()==[\n                LIVE_FIXTURE_TEST+': test','','1 test, 0 benchmarks'], 'compile','artifact_profile')\n"),
  (659,662,'1d869fcc67f25a1dcdac215e90d13626478d5f2eeccf93fe94ca56b723d546df',b"    require(pin(inputs/'coordinator-production')['sha256'] != pin(inputs/'coordinator-observed')['sha256'],\n            'compile','artifact_profile')\n"),
  (672,673,'c0af30dfb58b635f4e11fbd6cfa390c52fd1d57cddca0b0184433ea0570abf42',b"    for name in I.ARTIFACT_FILES:args+=['--'+name,str(inputs/name)]\n"),
  (715,716,'135d194bc4ed8fd78942a725662ef6322c5bfa50b645b36152c0a79d4e406561',b'            for name in A.NAMES:\n'),
  (735,739,'9b4156ae16b73e615f6cdfdace3901928fb0ceb7f2f4d986ab8721a7c1ca30f7',b''),
  (749,750,'7206e8c4f0a4ec1bf744e210511fffa4f34910c09cb4f193963a3f27aaa278ca',b"    expected = {'wp-financial-' + token + '-' + mode for mode in MODES}\n"),
  (795,796,'f92a88ef75229aa87196ac1362ac0d1ffce1b82c2b464a1ca1ceb0a890c58429',b''),
  (831,832,'d40e11bfe1d1ce954b5aa205b6b52e43bb99c5a628a4283da1a641bce4abd094',b"        'command': cfg.get('Cmd') in (None, []),\n"),
  (1011,1022,'c1ed43159f115f9389a45c0d5ae27eacf61e310d7b4431b5d11fc9a36d20938e',b''),
  (1024,1026,'abc79e303fe641b4032c4c7d43be66e100b6a1eedb6ed4e7f8f9ee055563b6b7',b'    records = RuntimeRecords(mode,I.profile())\n'),
  (1038,1039,'6cf92478cac3d4ec84ba261884d67f65febfee2d806cba5aae5911594e664f35',b"        docker(args + [image_id], 'container', limit=4096)\n"),
  (1042,1043,'b426e932de99ed078fd8cec94b12838b93ac0f27dc058be10e6975d17deb5303',b'            seconds=1830, limit=16384, on_line=records)\n'),
  (1060,1061,'c29b043b37c6d1f546ab28640244e4999313b173e11224ed32077f51e180ab37',b"    return result, bool(result and result.get('native_oracle_verified') is True and removed and first is None)\n"),
  (1175,1176,'c2ac490bd8f0766c74f4c88d201a92ac2643ef8d3a1bce607a3c78369b548dcc',b'    for mode in MODES:\n'),
  (1221,1223,'7781079a82832e3615eaeca43b51444291106ebb45de7d43daa429755533ce81',b''),
  (1230,1231,'0ce7cb6f0a4f923233136b03470b7cabc8655a22eeacff1db101e22f6c4c047e',b''),
  (1234,1248,'190e5d1eea28840bd4ab0b68e39598e21e516a71b6e693f09e1f1552546f3415',b"            emit('SOURCE',dict(source=sha,profile=I.profile(),\n                semantic_assisted_host_observation=I.profile()==P.C.SEMANTIC_PROFILE,toolchain='1.99.0',container_base=BASE,\n                cargo_lock_sha256=hashlib.sha256((REPO/'Cargo.lock').read_bytes()).hexdigest(),\n                financial_session_seconds=1800,original_fixture_ceiling_seconds=900,\n                active_financial_witnesses=7,retained_inert_witnesses=6,external_native_witness=True,\n                public_chain_verified=False,dispatch_requested=False))\n"),
  (1266,1278,'8c4c7dcdb64f243900ebad3709011fc7afe0e044d56bf9025ac81f97e60d7fea',b"                    exact_source(sha);result,passed=run_case('external',image_id,token,sha)\n"),
  (1285,1286,'03945727aec73c6cdff9aadd0eb0cbc14c59148d3a81201b3f8781a0ed7cdc3f',b''),
  (1295,1300,'3cb27b9f25d1e722aec6743ddc0997224b8e48ab193bf3a89b695b3dc1b15d0e',b''),
 )),
}
class IntegrationTests(unittest.TestCase):
 def legacy_current_script_bytes(self,relative):
  current=(ROOT/relative).read_bytes()
  specification=CURRENT_DURABLE_PROFILE_INVERSES.get(relative)
  if specification is None:return current
  current_pin,old_pin,spans=specification
  self.assertEqual(hashlib.sha256(current).hexdigest(),current_pin,'current source whole-byte pin')
  lines=current.splitlines(keepends=True);restored=[];cursor=0
  for first,last,span_pin,prior in spans:
   self.assertTrue(type(first) is int and type(last) is int and cursor<=first<=last<=len(lines))
   selected=b''.join(lines[first:last])
   self.assertEqual(hashlib.sha256(selected).hexdigest(),span_pin,'exact current inverse span')
   self.assertIs(type(prior),bytes)
   restored.extend((b''.join(lines[cursor:first]),prior));cursor=last
  restored.append(b''.join(lines[cursor:]));legacy=b''.join(restored)
  self.assertEqual(hashlib.sha256(legacy).hexdigest(),old_pin,'exact whole P92 byte inverse')
  return legacy
 def legacy_gate_bytes(self):
  # Assert the actual new gate first. Only the following static legacy-wiring
  # view is restored; the current selected runtime remains durable V2.
  current=(ROOT/'scripts/qualification-gate-mode').read_bytes()
  self.assertEqual(current,b'financial-durable-v2\n')
  self.assertEqual(hashlib.sha256(current).hexdigest(),'87a7ba306e5bfafa8b340022ddf2757833bd19eb8815c7e486de210130cc16a6')
  legacy=current.replace(b'financial-durable-v2\n',b'financial-semantic\n')
  self.assertEqual(hashlib.sha256(legacy).hexdigest(),'ebadd1b086ae7c27c6a731049ef4c883841e9d7a710ac4e2b444677f130b38a2')
  return legacy
 def test_current_profile_inverse_rejects_crlf_at_existing_entry(self):
  from unittest.mock import patch
  path=ROOT/'scripts/ci-financial-artifacts.py';original=pathlib.Path.read_bytes
  current=original(path);self.assertIn(b'\n',current)
  changed=current.replace(b'\n',b'\r\n')
  self.assertNotEqual(changed,current)
  # Call the existing owning guard itself, not just the inverse helper. Raw
  # CRLF mutation must fail before any restoration or historical expectation.
  with patch.object(pathlib.Path,'read_bytes',lambda selected:changed if selected==path else original(selected)):
   with self.assertRaisesRegex(AssertionError,'current source whole-byte pin'):
    self.test_p40_parser_and_cleanup_exact_current_sources()
 def test_concrete_p40_h41_v2_plan(self):
  p=json.loads((HERE/'plan.json').read_text());self.assertEqual(p['harness'],{'repository': 'stanleykosi/pactloom', 'source': '3fc27434f7ee5d2af5f71c9d9010b982bedf74dd', 'source_tree': '2f70ddbbf2e740ed3001a117a30f479429fd125a'})
  self.assertEqual(L.validate_plan(p),p)
  self.assertEqual(p['producer'],L.V.PRODUCER);self.assertEqual(p['artifact_pins'],L.V.ARTIFACT_PINS);self.assertEqual(p['api_pins'],L.V.API_PINS)
  self.assertEqual(p['manifest_version'],2);self.assertEqual(p['build_recipe_version'],2);self.assertEqual(p['version'],6)
  self.assertEqual(p['artifact_pins']['artifact_id'],12491706804)
  self.assertEqual(p['reviewed_runtime_changes'],{'scripts/ci-financial-flow.py': 'fae619497e7fc66f9195169565c04ea7150bc74684ae99d221c2f8555c34ea0a', 'scripts/tests/test_ci_financial_observer.py': '6371af4423436b82c7ee654bb92798b6aa6cf96ea5818a70de1acd0155b354a3'})
 def test_p40_parser_and_cleanup_exact_current_sources(self):
  self.assertEqual(hashlib.sha256((HERE/'producer_artifacts.py').read_bytes()).hexdigest(),'c6d12ee5a132083ee97f5aee7fcda3b3dc270a794b90d3d65e18b271c3426682')
  self.assertEqual(hashlib.sha256(self.legacy_current_script_bytes('scripts/ci-financial-artifacts.py')).hexdigest(),'f31041a577f3fa0dc65f5880ac0a77d8fd145e53d4d576524ede3e2adbec29ce')
  for path,pin in L.CLEANUP_PINS.items():
   data=(HERE/path).read_bytes();self.assertEqual(hashlib.sha256(data).hexdigest(),pin)
   relative=str(pathlib.Path(path).relative_to('cleanup_snapshot'))
   # Historical P40 cleanup remains pinned; current comparison uses exact reviewed P70 bytes.
   fresh_changes={'scripts/ci-financial-container.py': '3b030ae61e24b7d8d36a4a32cb1c71d3c88fa2c43fa90420a66cce663fa11be2', 'scripts/ci-financial-image.py': '3609f2a672bd6db7e5f9edaa708877f11cff70e39be28644df0b3b50030b4633', 'scripts/ci-financial-contract.py': '8cf84b3a1f3a060e288368a1feccdd8f651fb80a9c0a49f3102f862241d17af0', 'scripts/ci-financial-external-output.py': 'e213c1c5304535e87d6fc4fc6931396a8e230b0ec3b2cec739c0d4291531bef5', 'scripts/ci-financial-observer.py': '0d446222a049704c4ed4832177801c9ed4c23f3db174702dda9087a8749284fb', 'scripts/ci-financial-scenario.py': '40013fad2d212e9031d40c10cf53d1969b281d369b0df3778164ac13ac20fbea', 'scripts/ci-financial-supervisor.py': '1fd28d86df843d9ebf46bf159b9cb8c1a2b0487d8a94f174d599b935b545c389', 'scripts/tests/test_ci_financial_observer.py': 'df7dd040c134a7c45655b9070b5b25bd72d8a446df570e0eea988f5b18d8111d', 'scripts/ci-financial-artifacts.py': 'f31041a577f3fa0dc65f5880ac0a77d8fd145e53d4d576524ede3e2adbec29ce'}
   if relative in fresh_changes:
    current=self.legacy_current_script_bytes(relative)
    self.assertEqual(hashlib.sha256(current).hexdigest(),fresh_changes[relative])
    if relative=='scripts/ci-financial-contract.py':
     # Exact P92 finite-schema inverse before the unchanged P91/P89 pin.
     changes=[(b"ACTOR_DRIVER_STAGES=frozenset(('Initialization', 'OriginalActors', 'Receive', 'Handle', 'Opening', 'PairBegin', 'PairPoll', 'EnrollmentBegin', 'ReceiptPoll', 'RedisclosurePoll', 'StatusPoll', 'DeliveryPoll', 'FinancialPoll', 'FinancialTransport', 'SourceRetention', 'WorkUnclassified', 'Cleanup', 'DisposalSend', 'EnrollmentPairingCheck', 'EnrollmentSessionCheck', 'EnrollmentPeerCheck', 'ManifestPairingCheck', 'ManifestSessionCheck', 'ManifestPeerCheck', 'PreconstructionCheck', 'WitnessWork', 'LeafProtocol', 'NormalDispose', 'AdmitReadAction', 'AdmitReadCurrent', 'AdmitReadDisplay', 'AdmitReadFinishCurrent', 'AdmitReadFinishCustody', 'AdmitReadFinishPhase', 'AdmitReadHistory', 'AdmitReadHistoryBounds', 'AdmitReadHistoryCallback', 'AdmitReadHistoryCallerDeadline', 'AdmitReadHistoryDigest', 'AdmitReadHistoryDisclosure', 'AdmitReadHistoryEventReplay', 'AdmitReadHistoryExchangeDeadline', 'AdmitReadHistoryFinalValidation', 'AdmitReadHistoryPageConnect', 'AdmitReadHistoryPageHandshake', 'AdmitReadHistoryPagePeerBinding', 'AdmitReadHistoryPageRequestBuild', 'AdmitReadHistoryPageRequestWrite', 'AdmitReadHistoryPageResponse', 'AdmitReadHistoryPageResponseRead', 'AdmitReadHistoryPageValidation', 'AdmitReadHistorySnapshotConnect', 'AdmitReadHistorySnapshotHandshake', 'AdmitReadHistorySnapshotPeerBinding', 'AdmitReadHistorySnapshotRequestBuild', 'AdmitReadHistorySnapshotRequestWrite', 'AdmitReadHistorySnapshotResponse', 'AdmitReadHistorySnapshotResponseRead', 'AdmitReadHistorySnapshotValidation', 'AdmitReadHistorySourceCallback', 'AdmitReadIntentDigest', 'AdmitReadPrepareIntent', 'AdmitReadPreparedSource', 'AdmitReadReceivedBinding', 'AdmitReadReport', 'AdmitReadRequestDigest', 'AdmitReadSourceAcquire', 'AdmitReadSourceAction', 'AdmitReadSourceAfter', 'AdmitReadSourceBefore', 'AdmitReadSourceBinding', 'AdmitReadSourceCallback', 'AdmitReadSourceCurrent', 'AdmitReadSourceLeasePermission', 'AdmitReadSourcePresentation', 'AdmitReadSourcePurpose', 'AdmitReadSourceRecords', 'AdmitReadSourceRetained', 'AdmitReadSourceRevision', 'AdmitReadSourceRevisionMissing', 'AdmitReadWitnessAction', 'AdmitReadWitnessBinding', 'AdmitReadWitnessCheck', 'AdmitReadWitnessCustody', 'AdmitReadWitnessDigest', 'AdmitReadWitnessPresentation', 'AdmitReadIntentAction', 'AdmitReadIntentAuthorityRequest', 'AdmitReadIntentCurrentRows', 'AdmitReadIntentFinancialRows', 'AdmitReadIntentHistoryDigest', 'AdmitReadIntentJournalAccount', 'AdmitReadIntentJournalIdentity', 'AdmitReadIntentJournalSchema', 'AdmitReadIntentOriginalRows', 'AdmitReadIntentReadPresentation', 'AdmitReadIntentReview', 'AdmitReadIntentReviewBinding', 'AdmitReadIntentReviewCeilings', 'AdmitReadIntentReviewDigest', 'AdmitReadIntentReviewMaterial', 'AdmitReadIntentReviewNested', 'AdmitReadIntentReviewShape', 'AdmitReadIntentRowsAccountUse', 'AdmitReadIntentRowsCurrentDisclosure', 'AdmitReadIntentRowsMaterial', 'AdmitReadIntentRowsOriginalDisclosure', 'AdmitReadIntentRowsOriginalLinks', 'AdmitReadIntentRowsSession', 'AdmitReadIntentRowsTransport', 'AdmitReadIntentScope', 'AdmitReadIntentSourceJournal', 'AdmitReadScopeAcquire', 'AdmitReadScopeClaims', 'AdmitReadScopeFixedInputs', 'AdmitReadScopeHistory', 'AdmitReadScopeOriginal', 'AdmitReadScopePermission', 'AdmitReadScopePolicy', 'AdmitReadScopePolicyBinding', 'AdmitReadScopePolicyExport', 'AdmitReadScopePolicyReturns', 'AdmitReadScopeRecipient', 'AdmitReadScopeTerms', 'HistoryMonitorCheck', 'HistoryCleanupDeadline', 'HistoryRequestReceive', 'HistoryRequestOrder', 'HistoryWorkerStart', 'HistoryServeHandoff', 'HistoryEventOrder', 'HistoryDisplaySend', 'HistoryServingSend', 'HistoryWorkerJoin', 'HistoryWorkerFailure', 'HistoryWorkerUnexpectedReturn', 'HistoryFailureSend', 'HistoryDisposedSend', 'HistoryPurposeClosedSend', 'HistoryCleanupRetain', 'HistoryRetainedReceiveError', 'HistoryFinishError', 'HistoryRetirementPrepareError', 'HistoryRetirementError', 'HistoryRetirementNativePauseTicket', 'HistoryRetirementNativePauseWait', 'HistoryRetirementHostQuiescence', 'HistoryRetirementPurposeClose', 'HistoryRetirementOwnedStopReap', 'HistoryRetirementHostResume', 'HistoryRetirementNativeResume', 'FinancialWorkerJoinPanic', 'FinancialWorkerResult', 'AdmitCommitBeforeTransport', 'AdmitCommitAfterTransport', 'AdmitTransport', 'AdmitTransportCallerDeadline', 'AdmitTransportExchangeDeadline', 'AdmitTransportSourceCallback', 'AdmitTransportRequestValidation', 'AdmitTransportBinding', 'AdmitTransportConnect', 'AdmitTransportHandshake', 'AdmitTransportPeerBinding', 'AdmitTransportRequestBuild', 'AdmitTransportRequestWrite', 'AdmitTransportResponseRead', 'AdmitTransportResponse', 'AdmitTransportSnapshotValidation', 'AdmitTransportCommittedHeadValidation', 'AdmitTransportFinalValidation', 'WitnessFirstFailureObserved', 'WriterReceiptClockRestoreError', 'WriterAcquireReceiveError', 'WriterActivateReceiveError', 'RestrictionCore', 'RestrictionSession', 'RestrictionAlreadyRevoked', 'RestrictionPairService', 'RestrictionOwner1V3Active', 'RestrictionOwner2V3Active', 'RestrictionOwner1EntryPreparing', 'RestrictionOwner2EntryPreparing', 'RestrictionOwner1EntryCustody', 'RestrictionOwner2EntryCustody', 'RestrictionOwner1EntryAction', 'RestrictionOwner2EntryAction', 'RestrictionOwner1ContinueMissing', 'RestrictionOwner2ContinueMissing', 'RestrictionOwner1ContinuePreparing', 'RestrictionOwner2ContinuePreparing', 'RestrictionOwner1ContinueBindingMissing', 'RestrictionOwner2ContinueBindingMissing', 'RestrictionOwner1ContinueBinding', 'RestrictionOwner2ContinueBinding', 'RestrictionOwner1ReadBindingMissing', 'RestrictionOwner2ReadBindingMissing', 'RestrictionOwner1ReadCurrent', 'RestrictionOwner2ReadCurrent', 'RestrictionOwner1AdmitActive', 'RestrictionOwner2AdmitActive', 'RestrictionOwner1WriterActive', 'RestrictionOwner2WriterActive', 'RestrictionOwner1ActivateActive', 'RestrictionOwner2ActivateActive', 'RestrictionOwner1WitnessActive', 'RestrictionOwner2WitnessActive', 'RestrictionOwner1HistoryActive', 'RestrictionOwner2HistoryActive', 'RestrictionOwner1SigningActive', 'RestrictionOwner2SigningActive', 'SignedResultOwner1OriginalDeadline', 'SignedResultOwner2OriginalDeadline', 'SignedResultOwner1EntryBounds', 'SignedResultOwner2EntryBounds', 'SignedResultOwner1SharedWallRead', 'SignedResultOwner2SharedWallRead', 'SignedResultOwner1SharedWallRejected', 'SignedResultOwner2SharedWallRejected', 'SignedResultOwner1ServiceWallBefore', 'SignedResultOwner2ServiceWallBefore', 'SignedResultOwner1ServiceWallExpired', 'SignedResultOwner2ServiceWallExpired', 'SignedResultOwner1Restricted', 'SignedResultOwner2Restricted', 'SignedResultOwner1SigningPhase', 'SignedResultOwner2SigningPhase', 'SignedResultOwner1RetiredIndex', 'SignedResultOwner2RetiredIndex', 'SignedResultOwner1RetiredRoot', 'SignedResultOwner2RetiredRoot', 'SignedResultOwner1Core', 'SignedResultOwner2Core', 'SignedResultOwner1FinalRestricted', 'SignedResultOwner2FinalRestricted', 'SigningOwner1RetiredMissing', 'SigningOwner2RetiredMissing'))\n", b"ACTOR_DRIVER_STAGES=frozenset(('Initialization', 'OriginalActors', 'Receive', 'Handle', 'Opening', 'PairBegin', 'PairPoll', 'EnrollmentBegin', 'ReceiptPoll', 'RedisclosurePoll', 'StatusPoll', 'DeliveryPoll', 'FinancialPoll', 'FinancialTransport', 'SourceRetention', 'WorkUnclassified', 'Cleanup', 'DisposalSend', 'EnrollmentPairingCheck', 'EnrollmentSessionCheck', 'EnrollmentPeerCheck', 'ManifestPairingCheck', 'ManifestSessionCheck', 'ManifestPeerCheck', 'PreconstructionCheck', 'WitnessWork', 'LeafProtocol', 'NormalDispose', 'AdmitReadAction', 'AdmitReadCurrent', 'AdmitReadDisplay', 'AdmitReadFinishCurrent', 'AdmitReadFinishCustody', 'AdmitReadFinishPhase', 'AdmitReadHistory', 'AdmitReadHistoryBounds', 'AdmitReadHistoryCallback', 'AdmitReadHistoryCallerDeadline', 'AdmitReadHistoryDigest', 'AdmitReadHistoryDisclosure', 'AdmitReadHistoryEventReplay', 'AdmitReadHistoryExchangeDeadline', 'AdmitReadHistoryFinalValidation', 'AdmitReadHistoryPageConnect', 'AdmitReadHistoryPageHandshake', 'AdmitReadHistoryPagePeerBinding', 'AdmitReadHistoryPageRequestBuild', 'AdmitReadHistoryPageRequestWrite', 'AdmitReadHistoryPageResponse', 'AdmitReadHistoryPageResponseRead', 'AdmitReadHistoryPageValidation', 'AdmitReadHistorySnapshotConnect', 'AdmitReadHistorySnapshotHandshake', 'AdmitReadHistorySnapshotPeerBinding', 'AdmitReadHistorySnapshotRequestBuild', 'AdmitReadHistorySnapshotRequestWrite', 'AdmitReadHistorySnapshotResponse', 'AdmitReadHistorySnapshotResponseRead', 'AdmitReadHistorySnapshotValidation', 'AdmitReadHistorySourceCallback', 'AdmitReadIntentDigest', 'AdmitReadPrepareIntent', 'AdmitReadPreparedSource', 'AdmitReadReceivedBinding', 'AdmitReadReport', 'AdmitReadRequestDigest', 'AdmitReadSourceAcquire', 'AdmitReadSourceAction', 'AdmitReadSourceAfter', 'AdmitReadSourceBefore', 'AdmitReadSourceBinding', 'AdmitReadSourceCallback', 'AdmitReadSourceCurrent', 'AdmitReadSourceLeasePermission', 'AdmitReadSourcePresentation', 'AdmitReadSourcePurpose', 'AdmitReadSourceRecords', 'AdmitReadSourceRetained', 'AdmitReadSourceRevision', 'AdmitReadSourceRevisionMissing', 'AdmitReadWitnessAction', 'AdmitReadWitnessBinding', 'AdmitReadWitnessCheck', 'AdmitReadWitnessCustody', 'AdmitReadWitnessDigest', 'AdmitReadWitnessPresentation', 'AdmitReadIntentAction', 'AdmitReadIntentAuthorityRequest', 'AdmitReadIntentCurrentRows', 'AdmitReadIntentFinancialRows', 'AdmitReadIntentHistoryDigest', 'AdmitReadIntentJournalAccount', 'AdmitReadIntentJournalIdentity', 'AdmitReadIntentJournalSchema', 'AdmitReadIntentOriginalRows', 'AdmitReadIntentReadPresentation', 'AdmitReadIntentReview', 'AdmitReadIntentReviewBinding', 'AdmitReadIntentReviewCeilings', 'AdmitReadIntentReviewDigest', 'AdmitReadIntentReviewMaterial', 'AdmitReadIntentReviewNested', 'AdmitReadIntentReviewShape', 'AdmitReadIntentRowsAccountUse', 'AdmitReadIntentRowsCurrentDisclosure', 'AdmitReadIntentRowsMaterial', 'AdmitReadIntentRowsOriginalDisclosure', 'AdmitReadIntentRowsOriginalLinks', 'AdmitReadIntentRowsSession', 'AdmitReadIntentRowsTransport', 'AdmitReadIntentScope', 'AdmitReadIntentSourceJournal', 'AdmitReadScopeAcquire', 'AdmitReadScopeClaims', 'AdmitReadScopeFixedInputs', 'AdmitReadScopeHistory', 'AdmitReadScopeOriginal', 'AdmitReadScopePermission', 'AdmitReadScopePolicy', 'AdmitReadScopePolicyBinding', 'AdmitReadScopePolicyExport', 'AdmitReadScopePolicyReturns', 'AdmitReadScopeRecipient', 'AdmitReadScopeTerms', 'HistoryMonitorCheck', 'HistoryCleanupDeadline', 'HistoryRequestReceive', 'HistoryRequestOrder', 'HistoryWorkerStart', 'HistoryServeHandoff', 'HistoryEventOrder', 'HistoryDisplaySend', 'HistoryServingSend', 'HistoryWorkerJoin', 'HistoryWorkerFailure', 'HistoryWorkerUnexpectedReturn', 'HistoryFailureSend', 'HistoryDisposedSend', 'HistoryPurposeClosedSend', 'HistoryCleanupRetain', 'HistoryRetainedReceiveError', 'HistoryFinishError', 'HistoryRetirementPrepareError', 'HistoryRetirementError', 'HistoryRetirementNativePauseTicket', 'HistoryRetirementNativePauseWait', 'HistoryRetirementHostQuiescence', 'HistoryRetirementPurposeClose', 'HistoryRetirementOwnedStopReap', 'HistoryRetirementHostResume', 'HistoryRetirementNativeResume', 'FinancialWorkerJoinPanic', 'FinancialWorkerResult', 'AdmitCommitBeforeTransport', 'AdmitCommitAfterTransport', 'AdmitTransport', 'AdmitTransportCallerDeadline', 'AdmitTransportExchangeDeadline', 'AdmitTransportSourceCallback', 'AdmitTransportRequestValidation', 'AdmitTransportBinding', 'AdmitTransportConnect', 'AdmitTransportHandshake', 'AdmitTransportPeerBinding', 'AdmitTransportRequestBuild', 'AdmitTransportRequestWrite', 'AdmitTransportResponseRead', 'AdmitTransportResponse', 'AdmitTransportSnapshotValidation', 'AdmitTransportCommittedHeadValidation', 'AdmitTransportFinalValidation', 'WitnessFirstFailureObserved', 'WriterReceiptClockRestoreError', 'WriterAcquireReceiveError', 'WriterActivateReceiveError', 'RestrictionCore', 'RestrictionSession', 'RestrictionAlreadyRevoked', 'RestrictionPairService', 'RestrictionOwner1V3Active', 'RestrictionOwner2V3Active', 'RestrictionOwner1EntryPreparing', 'RestrictionOwner2EntryPreparing', 'RestrictionOwner1EntryCustody', 'RestrictionOwner2EntryCustody', 'RestrictionOwner1EntryAction', 'RestrictionOwner2EntryAction', 'RestrictionOwner1ContinueMissing', 'RestrictionOwner2ContinueMissing', 'RestrictionOwner1ContinuePreparing', 'RestrictionOwner2ContinuePreparing', 'RestrictionOwner1ContinueBindingMissing', 'RestrictionOwner2ContinueBindingMissing', 'RestrictionOwner1ContinueBinding', 'RestrictionOwner2ContinueBinding', 'RestrictionOwner1ReadBindingMissing', 'RestrictionOwner2ReadBindingMissing', 'RestrictionOwner1ReadCurrent', 'RestrictionOwner2ReadCurrent', 'RestrictionOwner1AdmitActive', 'RestrictionOwner2AdmitActive', 'RestrictionOwner1WriterActive', 'RestrictionOwner2WriterActive', 'RestrictionOwner1ActivateActive', 'RestrictionOwner2ActivateActive', 'RestrictionOwner1WitnessActive', 'RestrictionOwner2WitnessActive', 'RestrictionOwner1HistoryActive', 'RestrictionOwner2HistoryActive', 'RestrictionOwner1SigningActive', 'RestrictionOwner2SigningActive'))\n"), (b"\n# Returned SignedResult/retired-missing checks are Coordinator-local only.\nACTOR_SIGNED_RESULT_STAGES=frozenset(('SignedResultOwner1OriginalDeadline', 'SignedResultOwner2OriginalDeadline', 'SignedResultOwner1EntryBounds', 'SignedResultOwner2EntryBounds', 'SignedResultOwner1SharedWallRead', 'SignedResultOwner2SharedWallRead', 'SignedResultOwner1SharedWallRejected', 'SignedResultOwner2SharedWallRejected', 'SignedResultOwner1ServiceWallBefore', 'SignedResultOwner2ServiceWallBefore', 'SignedResultOwner1ServiceWallExpired', 'SignedResultOwner2ServiceWallExpired', 'SignedResultOwner1Restricted', 'SignedResultOwner2Restricted', 'SignedResultOwner1SigningPhase', 'SignedResultOwner2SigningPhase', 'SignedResultOwner1RetiredIndex', 'SignedResultOwner2RetiredIndex', 'SignedResultOwner1RetiredRoot', 'SignedResultOwner2RetiredRoot', 'SignedResultOwner1Core', 'SignedResultOwner2Core', 'SignedResultOwner1FinalRestricted', 'SignedResultOwner2FinalRestricted', 'SigningOwner1RetiredMissing', 'SigningOwner2RetiredMissing'))\nACTOR_SIGNED_MINIMUM_STAGES=frozenset(('SignedResultOwner1OriginalDeadline','SignedResultOwner2OriginalDeadline'))\n# minimum_bounds bits: service=1, writer=2, writer_wall=4, entry.original_source=8.\n", b''), (b"def validate_actor_failure_facts(facts,role=None):\n    exact(facts,('version','driver','listener','origin'))\n    require(type(facts['version']) is int and facts['version']==1,'record_shape')\n    require(facts['driver'] is not None,'record_shape')\n    if role is not None:require(role in ('Signer1','Signer2') or facts['listener'] is None,'role')\n    for slot,stages in (('driver',ACTOR_DRIVER_STAGES),('listener',ACTOR_LISTENER_STAGES),('origin',ACTOR_ORIGIN_STAGES)):\n        part=facts[slot]\n        if part is None:continue\n        minimum=slot=='driver' and type(part) is dict and type(part.get('stage')) is str and part['stage'] in ACTOR_SIGNED_MINIMUM_STAGES\n        exact(part,('stage','class','peer') if slot=='origin' else (('stage','class','minimum_bounds') if minimum else ('stage','class')))\n        require(type(part['stage']) is str and part['stage'] in stages,'record_shape')\n        require(type(part['class']) is str and part['class'] in ACTOR_CLASSES,'record_shape')\n        if slot=='driver' and part['stage'] in ACTOR_SIGNED_RESULT_STAGES:\n            require(role=='Coordinator','role')\n        if minimum:require(type(part['minimum_bounds']) is int and 1<=part['minimum_bounds']<=15,'record_shape')\n        if slot=='origin':require(part['peer'] is None or (type(part['peer']) is str and part['peer'] in ACTOR_ROLES),'record_shape')\n    return facts\n\n", b"def validate_actor_failure_facts(facts,role=None):\n    exact(facts,('version','driver','listener','origin'))\n    require(type(facts['version']) is int and facts['version']==1,'record_shape')\n    require(facts['driver'] is not None,'record_shape')\n    if role is not None:require(role in ('Signer1','Signer2') or facts['listener'] is None,'role')\n    for slot,stages in (('driver',ACTOR_DRIVER_STAGES),('listener',ACTOR_LISTENER_STAGES),('origin',ACTOR_ORIGIN_STAGES)):\n        part=facts[slot]\n        if part is None:continue\n        exact(part,('stage','class','peer') if slot=='origin' else ('stage','class'))\n        require(type(part['stage']) is str and part['stage'] in stages,'record_shape')\n        require(type(part['class']) is str and part['class'] in ACTOR_CLASSES,'record_shape')\n        if slot=='origin':require(part['peer'] is None or (type(part['peer']) is str and part['peer'] in ACTOR_ROLES),'record_shape')\n    return facts\n\n")]
     for remove,restore in changes:
      self.assertEqual(current.count(remove),1);current=current.replace(remove,restore,1)
     self.assertEqual(hashlib.sha256(current).hexdigest(),'c59d312195e44ccb37f14395c0fedf108436848d40d0326852a0e0b185c2d738')
     appended=b"RelayPump RelayFinish ParkedMaterialBounds'.split())"
     self.assertEqual(current.count(appended),1)
     restored=current.replace(appended,b"RelayPump RelayFinish'.split())",1)
     self.assertEqual(hashlib.sha256(restored).hexdigest(),'482fd5b84bf4589ede1dc6cd24b2b771e98d4522e9c24bb4e8f124726418fd20')
   else:self.assertEqual(data,b'financial-semantic\n' if path.endswith('/qualification-gate-mode') else (ROOT/relative).read_bytes())
 def test_cleanup_dependency_closure_imports_without_execution(self):
  s=TRUSTED.module('cleanup_closure_probe',L.HERE/'cleanup_snapshot/scripts/ci-financial-supervisor.py')
  self.assertEqual(s.A.MANIFEST_VERSION,2);self.assertEqual(s.A.recipe(L.V.QUALIFICATION_PROFILE),L.V.A.recipe(L.V.QUALIFICATION_PROFILE))
 def test_mandatory_tests_and_cleanup_remain_wired(self):
  text=(HERE/'launch_adapter.py').read_text()
  self.assertIn("'scripts/ci-financial-launch-tests.py'",text);self.assertIn("'test*financial*.py'",text)
  self.assertIn('clean=S.cleanup(token,tag)',text);self.assertIn('clean=trusted_cleanup(trusted)',text)
  self.assertNotIn('S.build_inputs(',text);self.assertNotIn("'cargo'",text)
 def test_exact_private_workflow_wiring(self):
  self.assertEqual(self.legacy_gate_bytes(),b'financial-semantic\n')
  w=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
  titles=('Financial recipe and projection gates (no build or fixture)','Fresh exact-source financial build (no runtime fixture)','Preserve exact credential-free compiled financial bundle','Financial image and native runtime (verified same-job fresh bundle)')
  positions=[w.index('      - name: '+title) for title in titles]
  self.assertEqual(positions,sorted(positions))
  blocks=[w.split('      - name: '+title,1)[1].split('      - name:',1)[0] for title in titles]
  for block in blocks:self.assertIn("steps.mode.outputs.gate == 'financial-semantic'",block)
  self.assertIn('scripts/ci-financial-launch-tests.py',blocks[0]);self.assertIn("-p 'test*financial*.py'",blocks[0])
  self.assertIn('scripts/ci-financial-supervisor.py build',blocks[1])
  self.assertIn("steps.financial_build.outcome == 'success'",blocks[2]);self.assertIn("steps.financial_build.outputs.artifact_bundle_ready == 'true'",blocks[2])
  self.assertIn("steps.financial_build.outcome == 'success'",blocks[3]);self.assertIn('test "$FINANCIAL_BUILD_READY" = true',blocks[3])
  self.assertIn('scripts/ci-financial-supervisor.py run-built',blocks[3])
  self.assertIn('steps.financial_build.outputs.artifact_bundle_sha256',blocks[3]);self.assertIn('steps.financial_build.outputs.artifact_bundle_size',blocks[3])
  for title in ('Fetch exact independent producer P and reviewed harness H without credentials','Acquire exact producer bundle with isolated read token','Actual synthetic financial runtime using verified producer binaries (not a fresh build)','Preserved P35 preparation, owned admissions and process-death reopen diagnostic (NOT full flow)'):
   block=w.split('      - name: '+title,1)[1].split('      - name:',1)[0]
   condition=next(line for line in block.splitlines() if line.strip().startswith('if:'))
   self.assertNotIn("gate == 'financial-semantic'",condition)
  cleanup=w.split('      - name: Verify financial containers, temporary images and build cache removed',1)[1].split('      - name:',1)[0]
  self.assertIn("always() &&",cleanup);self.assertIn("gate == 'financial-semantic'",cleanup)
  self.assertIn('scripts/ci-financial-supervisor.py cleanup',cleanup)
if __name__=='__main__':unittest.main()

class CleanupProfileTests(unittest.TestCase):
 def test_current_p40_cleanup_main_has_pinned_profile_input(self):
  from unittest.mock import patch
  import tempfile,os
  s=TRUSTED.module('cleanup_main_probe',L.HERE/'cleanup_snapshot/scripts/ci-financial-supervisor.py')
  with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,{'RUNNER_TEMP':tmp}),patch.object(s,'context',return_value=('a'*40,'token')),patch.object(s.sys,'argv',['supervisor','cleanup']),patch.object(s,'cleanup',return_value=True) as cleanup,patch.object(s,'emit'):
   self.assertEqual(s.main(),0);cleanup.assert_called_once()

class IdenticalSourceTests(unittest.TestCase):
 def test_zero_delta_only_for_exact_producer_identity(self):
  p=json.loads((HERE/'plan.json').read_text());p['harness']={k:L.V.PRODUCER[k] for k in ('repository','source','source_tree')};p['reviewed_runtime_changes']={};L.validate_plan(p)
  import copy
  for key in ('source','source_tree','repository'):
   changed=copy.deepcopy(p);changed['harness'][key]='f'*40
   with self.assertRaises(L.V.A.Rejected):L.validate_plan(changed)
 def test_zero_delta_still_rejects_native_or_annex_change(self):
  inv={'Cargo.lock':'a'*64,'scripts/ci-financial-flow.py':'b'*64}
  self.assertEqual(L.V.equivalent(inv,inv),[])
  with self.assertRaises(L.V.A.Rejected):L.V.equivalent(inv,{**inv,'Cargo.lock':'c'*64})
  with self.assertRaises(L.V.A.Rejected):L.V.equivalent(inv,inv,{})

class WorkflowCustodyTests(unittest.TestCase):
 def test_exact_p_h_and_credential_cleanup_boundaries(self):
  w=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
  self.assertEqual(w.count('fetch_exact P 99501f5853a4516fc94a6361f39cb4373048f01f'),1)
  self.assertEqual(w.count('fetch_exact H 3fc27434f7ee5d2af5f71c9d9010b982bedf74dd'),1)
  self.assertEqual(w.count('FINANCIAL_ARTIFACT_READ_TOKEN:'),1)
  runtime=w.split('      - name: Actual synthetic financial runtime',1)[1]
  self.assertNotIn('github.token',runtime);self.assertIn('env -i PATH=',runtime)
  self.assertIn("if: always() && steps.mode.outputs.gate == 'financial-semantic-reuse'",runtime)
  self.assertIn('launch_adapter.py" cleanup "${GITHUB_WORKSPACE}/source"',runtime)
 def test_mandatory_launcher_tests_and_no_native_smoke(self):
  w=(ROOT/'.github/workflows/durable-native-linux.yml').read_text()
  self.assertIn("unittest discover -s source/scripts/financial-runtime-reuse -p 'test_*.py'",w)
  smoke=w.split('      - name: Pre-runtime trusted cleanup smoke',1)[1].split('      - name:',1)[0]
  self.assertIn('launch_adapter.py" cleanup',smoke);self.assertNotIn('pristine-setup',smoke);self.assertNotIn(' run ',smoke)

