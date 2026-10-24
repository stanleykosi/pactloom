#!/usr/bin/env python3
"""Closed full-financial CI contract. Import does not launch or approve anything."""
import json
import math

PROFILE = 'coordinated-financial-full-native-v1'
EXTERNAL_PROFILE = 'coordinated-financial-external-pre-v3-witness-v1'
SEMANTIC_PROFILE = 'coordinated-financial-rendered-host-semantic-v1'
SCHEMA = 1
ORIGINAL_NS = 1_800_000_000_000
ACTION_NS = 120_000_000_000
MAX_RECORDS = 32768
MAX_RECORD_BYTES = 32768
MAX_TEXT_BYTES = 8192
MAX_WIDGETS = 128
MAX_NATIVE_COMMANDS = 524288
MAX_CAPTURES = 256
APP_ID = 'org.wholepact.CoordinatorFinancialQualification'
ROLES = ('Coordinator', 'Host', 'Signer1', 'Signer2',
         'Owner1BootstrapHistory', 'Owner1V3DeliveryAdmission', 'Owner1DeliveryAuditHistory',
         'Owner1FinancialReadHistory', 'Owner1FinancialContinuationAdmission', 'Owner1FinancialSigning',
         'Owner2BootstrapHistory', 'Owner2V3DeliveryAdmission', 'Owner2DeliveryAuditHistory',
         'Owner2FinancialReadHistory', 'Owner2FinancialContinuationAdmission', 'Owner2FinancialSigning',
         'CompletedPair')
WITNESSES = frozenset(ROLES[4:])
ACTIVE_WITNESSES = frozenset(r for r in WITNESSES if 'Financial' in r or r=='CompletedPair')
INERT_WITNESSES = WITNESSES - ACTIVE_WITNESSES
PARENTS = {role: ('Host' if role in ('Signer1', 'Signer2') else 'Coordinator') for role in ROLES[1:]}
SIGNER_STEPS = ('EntryOpened', 'Paired', 'Enrolled', 'ManifestAccepted', 'Redisclosed',
                'DeliveryPrepared', 'DeliveryReceived', 'AdmissionCommitted', 'AdmissionAudited',
                'FinancialEntryOpened', 'HistoryRetained', 'ContinuationSaved', 'ContinuationAdmitted',
                'WriterAcquired', 'WriterActivated', 'WalletPrepared', 'WalletObserved',
                'SignCommitted', 'SigningRetired', 'ReturnPrepared', 'ReturnFinished')
HOST_STEPS = ('Owner1AdmissionVerified', 'Owner1SigningRetired', 'Owner2AdmissionVerified',
              'Owner2SigningRetired', 'CompletedPairRetained', 'BothReturnsIntaken',
              'TransactionSavedVerified', 'NoDispatchSelected')
PHASES = frozenset('''Selecting FinancialSetupConfiguring FinancialSetupSelected V3Configuring
V3Preparing V3Review V3Confirm V3Password V3Opening V3Held V3PairReview V3Pairing V3Paired
V3EnrollmentReview V3Enrolling V3Enrolled V3ManifestReview V3Manifesting V3ManifestAccepted
V3RedisclosureReadReview V3RedisclosureReading V3RedisclosurePrepared V3RediscloseReview V3Redisclosing
V3Redisclosed V3OwnerConfiguring V3OwnerSelected V3PrepareReadReview V3PrepareReading V3Prepared
V3ReceiveReview V3Receiving V3Received V3AdmitReadReview V3AdmitReading V3AdmitReadRetained
V3AdmitReview V3AdmitArmed V3AdmitReady V3Admitting V3AdmissionRetained V3AuditReview V3Auditing V3Audited
Configuring Preparing EntryReview EntryConfirm Password Opening HistorySetupNeeded HistorySetupPreparing
HistorySetupReview HistoryPreparing HistoryReview HistoryStarting ReadReview ReadConfirm Reading
HistoryRetiring HistoryReady ContinuePreparing ContinueReview ContinueConfirm ContinueArmed Continuing
SetupNeeded SetupPreparing SetupReview AdmissionReview RetirementBlocked WriterFlow ActivateReadReview
ActivateReading ActivateReview ActivateArmed ActivateReady Activating Activated WalletPrepareReview
WalletPreparing WalletPrepared WalletObserveReview WalletObserving WalletObserved SignReadReview
SignReading SignPrepared SignExactReview SigningExact SignCommitted SigningRetiring SignedRetired
CompletedPairFlow ReturnReadReview ReturnReading ReturnPrepared ReturnExactReview ReturningExact
ReturnCompleted Waiting NormalFinishReview NormalClosing Revoked Finished'''.split())
SUBPHASES = frozenset('''None SetupNeeded SetupPreparing SetupReview ServicePreparing ServiceReview
ServiceStarting ReadReview Reading AcquireReview AcquireArmed Acquiring Acquired Configuring Preparing
Review Serving Retiring Finished Idle PreparingService ServeReview StartingService Failed Disposed Closed'''.split())
ACTIONS = frozenset('''SelectNextV3 ConfigureV3 ConfigureFinancialSetup SelectFinancialSetup BeginV3 ConfirmV3 PasswordV3
PasswordSubmit ReviewV3Pair FinalV3Pair ReviewV3Enrollment FinalV3Enrollment ReviewV3Manifest FinalV3Manifest
ReviewV3RedisclosureRead FinalV3RedisclosureRead ReviewV3Redisclose FinalV3Redisclose ConfigureV3Owner
SelectV3Owner ReviewV3PrepareRead FinalV3PrepareRead ReviewV3Receive FinalV3Receive ReviewV3AdmitRead
FinalV3AdmitRead ReviewV3Admit ArmV3Admit FinalV3Admit ReviewV3Audit FinalV3Audit Configure Begin
EntryConfirm EnterPassword PrepareHistory SetupHistory ServeHistory ReadConfirm Read BeginContinue
ContinueConfirm ArmContinue PrepareSetup Setup ArmSigner ArmWitness AdmitFinal WriterAction ActivateRead
ActivateArm ActivateFinal WalletPrepare WalletObserve SignRead SignExact RetireSigning ParkFinancial
ResumeFinancial PrepareCompletedPair CompletedPairAction ReturnRead ReturnExact ShowContinuationSelector
SaveContinuationSelector SaveResultSelector BeginHostLine HostSubmit HostEditor SourcePassword ReviewBody
SignerReviewBody WitnessReviewBody ReviewAcknowledgement WitnessReviewAcknowledgement SignerReviewAcknowledgement HostOutput ScrollRegion
NormalFinish Close ContinueSelectorPath ResultSelectorPath'''.split())
FIELDS = frozenset('''V3Selection WriterConfiguration PinnedServerCertificate OwnerCertificateDerHex SourceRoot SourceIdentity AccountId NetworkProfile SelectedJournal MaterialRoot
HostProfile HostWorkspace HostCommands StorageKey ServerCertificate ServerPrivateKey TrustedClientRoot
Endpoint ServerName WitnessId OwnerCertificate WriterCertificate WriterPrivateKey TrustedServerRoot
WalletConfiguration OwnerConfiguration FinancialSelection InitialReadSelection ContinueSelectorPath
ResultSelectorPath'''.split())
WIDGETS = ACTIONS | frozenset('Field:' + field for field in FIELDS)
ERRORS = frozenset('''contract record_limit record_shape role lineage order replay deadline observer_missing
observer_failure source_failure snapshot input_phase input_widget input_disabled input_budget sensitive_capture
fixture fixture_path fixture_secret fixture_deadline ocr ocr_pin ocr_prompt unexpected_prompt process
cleanup missing_evidence normal_finish dispatch_forbidden transport'''.split())

class Rejected(Exception):
    def __init__(self, code):
        self.code = code if code in ERRORS else 'contract'
        super().__init__(self.code)

def require(condition, code='contract'):
    if not condition:
        raise Rejected(code)

def exact(value, keys, code='record_shape'):
    require(type(value) is dict and set(value) == set(keys), code)

def integer(value, low=0, high=2**63-1):
    return type(value) is int and low <= value <= high

def loads(raw, limit=MAX_RECORD_BYTES):
    require(type(raw) in (bytes, bytearray, str) and len(raw) <= limit, 'record_limit')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'record_shape')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Rejected('record_shape')))
    except (ValueError, UnicodeError, TypeError):
        raise Rejected('record_shape') from None

def validate_host_observation(h, facts):
    exact(h, ('revision','nonws_end','context_valid','entry','editor','view'), 'snapshot')
    require(integer(h['revision'],0,262144) and integer(h['nonws_end'],0,1048576),'snapshot')
    require(type(h['context_valid']) is bool and h['entry'] in ('Idle','Editing','Writing','Closed'),'snapshot')
    editor=h['editor']
    if h['entry']=='Editing':
        exact(editor,('ordinal','revision'),'snapshot')
        require(integer(editor['ordinal'],1,128) and integer(editor['revision'],0,262144)
                and editor['revision']==h['revision'] and facts['host_input'],'snapshot')
    else: require(editor is None,'snapshot')
    if h['entry']=='Writing': require(facts['host_input'],'snapshot')
    view=h['view']
    if view is not None:
        exact(view,('rect','nonws','rows'),'snapshot')
        require(h['context_valid'] and h['entry']=='Idle' and not facts['host_input'] and not facts['secret_input'],'snapshot')
        require(integer(view['nonws'],1,8192) and view['nonws']<=h['nonws_end'] and integer(view['rows'],1,32),'snapshot')
        outputs=[w for w in facts['widgets'] if w['tag']=='HostOutput' and w['owner'] is None]
        require(len(outputs)==1 and outputs[0]['enabled'],'snapshot')
        r=view['rect']; outer=outputs[0]['rect']
        require(type(r) is list and len(r)==4 and all(type(x) in (int,float) and math.isfinite(x) for x in r),'snapshot')
        require(outer[0]<=r[0]<r[2]<=outer[2] and outer[1]<=r[1]<r[3]<=outer[3],'snapshot')
    return h

def validate_snapshot(facts, expected_profile=PROFILE):
    require(expected_profile in (PROFILE,EXTERNAL_PROFILE,SEMANTIC_PROFILE))
    original=facts
    if expected_profile==SEMANTIC_PROFILE:
        require(type(facts) is dict and 'host_view_id' in facts,'snapshot')
        reference=facts['host_view_id']
        require(reference is None or integer(reference,1,512),'snapshot')
        facts={k:v for k,v in facts.items() if k!='host_view_id'}
    exact(facts, ('phase','subphase','owner','view_generation','focused','secret_input','host_input',
                  'pixels_per_point','viewport','widgets','host_observation'))
    require(facts['phase'] in PHASES and facts['subphase'] in SUBPHASES, 'snapshot')
    require(facts['owner'] in (None, 'Signer1', 'Signer2'), 'snapshot')
    require(integer(facts['view_generation'], 1), 'snapshot')
    require(all(type(facts[key]) is bool for key in ('focused','secret_input','host_input')), 'snapshot')
    scale = facts['pixels_per_point']
    require(type(scale) in (int,float) and math.isfinite(scale) and .5 <= scale <= 4, 'snapshot')
    require(facts['viewport'] == [1280,800], 'snapshot')
    require(type(facts['widgets']) is list and len(facts['widgets']) <= MAX_WIDGETS, 'snapshot')
    seen = set()
    for widget in facts['widgets']:
        exact(widget, ('tag','owner','rect','enabled'))
        require(widget['tag'] in WIDGETS and widget['owner'] in (None,'Signer1','Signer2') and
                type(widget['enabled']) is bool, 'snapshot')
        key = (widget['tag'],widget['owner']); require(key not in seen,'snapshot'); seen.add(key)
        rect = widget['rect']
        require(type(rect) is list and len(rect) == 4 and
                all(type(x) in (int,float) and math.isfinite(x) for x in rect), 'snapshot')
        x0,y0,x1,y1 = rect
        require(0 <= x0 < x1 <= 1280/scale and 0 <= y0 < y1 <= 800/scale, 'snapshot')
    validate_host_observation(facts['host_observation'],facts)
    if expected_profile==SEMANTIC_PROFILE and original['host_view_id'] is not None:
        h=facts['host_observation']
        require(facts['focused'] and not facts['host_input'] and not facts['secret_input']
                and h['context_valid'] and h['entry']=='Idle' and h['view'] is not None,'snapshot')
    return original

def validate_host_rendered_view(facts):
    exact(facts,('id','view_generation','revision','nonws_end','view','text'))
    require(integer(facts['id'],1,512) and integer(facts['view_generation'],1)
            and integer(facts['revision'],0,262144) and integer(facts['nonws_end'],0,1048576),'snapshot')
    v=facts['view'];exact(v,('rect','nonws','rows'),'snapshot')
    require(integer(v['nonws'],1,8192) and v['nonws']<=facts['nonws_end'] and integer(v['rows'],1,32),'snapshot')
    r=v['rect'];require(type(r) is list and len(r)==4 and all(type(x) in (int,float) and math.isfinite(x) for x in r),'snapshot')
    require(0<=r[0]<r[2]<=2560 and 0<=r[1]<r[3]<=1600,'snapshot')
    text=facts['text']
    require(type(text) is str and 0<len(text)<=8192 and all(c=='\n' or ' '<=c<='~' for c in text),'snapshot')
    require(text.count('\n')<v['rows'],'snapshot')
    require(sum(c not in ' \t\r\n\f\v' for c in text)==v['nonws'],'snapshot')
    return facts

def match_host_view(snapshot, view):
    validate_snapshot(snapshot,SEMANTIC_PROFILE);validate_host_rendered_view(view)
    h=snapshot['host_observation']
    require(snapshot['host_view_id']==view['id'] and view['view_generation']<=snapshot['view_generation']
            and view['revision']==h['revision'] and view['nonws_end']==h['nonws_end']
            and view['view']==h['view'],'snapshot')
    return view

def join_host_views(records, *, final=False):
    """Pure strict linkage over validated private records; never an input grant.

    Identical fresh IDs can follow an unobserved discarded/hidden pass. Only
    source occurrence positions, not view IDs, decide whether input is new.
    """
    return _join_host_views_validated(_validated_host_records(records),final=final)

def _validated_host_records(records):
    # Preserve public validation/check interleaving and first-error precedence.
    for record in records:
        validate_record(record,SEMANTIC_PROFILE)
        yield record

def _join_host_views_validated(records, *, final=False):
    # Private same-batch kernel: caller has validated each record already.
    # No persistence, authority, skipped linkage, or cross-read cache.
    active=None;pending=None;last_id=0;paired=0;sequence=0;generation=0
    for record in records:
        if record['role']!='Coordinator':continue
        require(record['sequence']==sequence+1,'order');sequence=record['sequence']
        kind=record['kind'];facts=record['facts']
        if kind=='HostRenderedView':
            require(pending is None and facts['id']==last_id+1,'replay')
            require(facts['view_generation']>generation,'snapshot')
            pending=facts;last_id=facts['id']
        elif kind=='UiSnapshot':
            require(facts['view_generation']>generation,'replay');generation=facts['view_generation']
            reference=facts['host_view_id']
            if reference is None:
                require(pending is None,'snapshot');active=None
            else:
                selected=pending if pending is not None else active
                require(selected is not None,'snapshot');match_host_view(facts,selected)
                if pending is not None:
                    require(selected['view_generation']==generation,'snapshot');paired+=1
                active=selected;pending=None
    if final:require(pending is None and paired>0,'missing_evidence')
    return active

def validate_record(record, expected_profile=PROFILE):
    require(expected_profile in (PROFILE,EXTERNAL_PROFILE,SEMANTIC_PROFILE))
    exact(record, ('schema','profile','role','sequence','elapsed_ns','kind','facts'))
    require(type(record['schema']) is int and record['schema'] == SCHEMA and record['profile'] == expected_profile, 'record_shape')
    require(record['role'] in ROLES and integer(record['sequence'],1,MAX_RECORDS) and
            integer(record['elapsed_ns'],0,ORIGINAL_NS), 'record_shape')
    kind, facts, role = record['kind'],record['facts'],record['role']
    if kind == 'Birth':
        exact(facts, ('pid','parent_pid','parent_role'))
        require(integer(facts['pid'],2,2**31-1) and integer(facts['parent_pid'],1,2**31-1), 'lineage')
        require(facts['parent_role'] == PARENTS.get(role), 'lineage')
    elif kind == 'SignerMilestone':
        exact(facts, ('owner','step'))
        require(role in ('Coordinator','Signer1','Signer2') and facts['owner'] in ('Signer1','Signer2') and
                facts['step'] in SIGNER_STEPS and (role == 'Coordinator' or role == facts['owner']), 'record_shape')
    elif kind == 'HostMilestone':
        exact(facts, ('step',)); require(role == 'Host' and facts['step'] in HOST_STEPS,'record_shape')
    elif kind in ('PurposeServing','PurposeDisposed','PurposeClosed'):
        exact(facts, ()); require(role in WITNESSES,'role')
    elif kind == 'InertStopped':
        exact(facts, ()); require(expected_profile in (EXTERNAL_PROFILE,SEMANTIC_PROFILE) and role in INERT_WITNESSES,'role')
    elif kind == 'OwnedReap':
        exact(facts, ('child','pid','exit_code'))
        require(facts['child'] in PARENTS and PARENTS[facts['child']] == role and
                integer(facts['pid'],2,2**31-1) and integer(facts['exit_code'],0,255), 'lineage')
    elif kind in ('NormalFinishAdmitted','NormalFinished','PtyHeld','PtyReleased'):
        exact(facts, ()); require(role == 'Coordinator','role')
    elif kind == 'UiSnapshot':
        require(role == 'Coordinator','role'); validate_snapshot(facts,expected_profile)
    elif kind == 'HostRenderedView':
        require(expected_profile==SEMANTIC_PROFILE and role=='Coordinator','role')
        validate_host_rendered_view(facts)
    elif kind == 'NativeFailureBoundary':
        require(expected_profile==SEMANTIC_PROFILE and role=='Coordinator','role')
        validate_native_failure_facts(facts)
    elif kind == 'HostReapObservation':
        require(expected_profile==SEMANTIC_PROFILE and role=='Coordinator','role')
        validate_host_reap_facts(facts)
    elif kind == 'HostFailureBoundary':
        require(expected_profile==SEMANTIC_PROFILE and role=='Host','role')
        validate_host_failure_facts(facts)
    elif kind in ('ActorFailureBoundary','ActorReapObservation'):
        require(expected_profile==SEMANTIC_PROFILE,'role')
        if kind=='ActorFailureBoundary':validate_actor_failure_facts(facts,role)
        else:validate_actor_reap_facts(facts,role)
    elif kind == 'Failure':
        exact(facts, ('code',)); require(facts['code'] in ERRORS,'record_shape')
    else:
        raise Rejected('record_shape')
    return record

# Two independent authenticated actors: no cross-process ordering or cause claim.
HOST_REAP_CONTEXTS=frozenset(('FinishPath','DropKillAttempted','RetirementTryReap'))
HOST_FAILURE_STAGES=frozenset('TerminalSetup OriginalCustody RelaySetup StartupSelection HostOpen CommandsPath CommandsFileRead CommandsDecode CommandsCheck Reviewer1Message Reviewer1EndpointWait LaterWorkflow NormalClose RunnerReturn PairEndpointValidate PairScopeValidate PairOriginalCustody PairConnect PairEnableCredentials PairVerifySigner PairObservePeer PairCloneObserver PairRequestWrite PairResponseRead PairResponseDecode PairResponseValidate PairResponseDigest PairChannelDigest PairInitialCurrent PairStatusOpen PairStatusRead PairStatusDecode PairStatusValidate PairFinalCurrent DeliverySourceOpen DeliverySourceInspection DeliverySourcePlan DeliveryRecipientPrepare DeliveryExportPreview DeliveryNativeCheck DeliverySourceCheck DeliverySourceScopePredicate DeliveryProofRolePredicate DeliveryMaterialActionPredicate DeliveryMaterialScopePredicate PreparationSourceBefore PreparationApproval PreparationSourceAfter HistoricalApprovalDeadline HistoricalApprovalForeground OriginalDisclosureSelector MaterialRestrictionCapture PairConfirmation ExportRecipientBinding ExportMetadataSource ExportMetadataMaterials ExportMetadataApproval ExportRecipientBind ExportFinalApproval ExportConsent ExportCommit ExportVerifiedWait AdmissionAuditRejected AdmissionAwaitingAudit AdmissionHistoryCurrent AdmissionHistoryDeadline AdmissionHistoryIntent AdmissionHistoryNonce AdmissionHistoryOpen AdmissionHistoryOwner AdmissionHistoryPrevious AdmissionHistoryResponseMatch AdmissionHistoryStatus AdmissionRequestChannel AdmissionRequestDeadline AdmissionRequestIntent AdmissionRequestNonce AdmissionResponseCheckAfter AdmissionResponseCheckBefore AdmissionResponseDeadlineAfter AdmissionResponseDeadlineBefore AdmissionResponseDecode AdmissionResponseFrame AdmissionResponsePeerAfter AdmissionResponsePeerBefore AdmissionUnknown PreparationReadinessCheckBefore PreparationReadinessPeerBefore PreparationReadinessDeadlineBefore PreparationReadinessFrame PreparationReadinessCheckAfter PreparationReadinessPeerAfter PreparationReadinessDeadlineAfter PreparationReadinessDecode'.split())
HOST_FAILURE_CLASSES=frozenset('Platform Terminal Permission Locked Invalid Authentication Storage Quarantined Unsupported Receipt RecoverySemantic RecoveryBackupUnsupported RecoveryFinancialUnsupported CompleteOriginRecoveryUnavailable HistoricalExportIncomplete GenerationArchiveIncomplete IoNotFound IoPermissionDenied IoInterrupted IoWouldBlock IoInvalidInput IoInvalidData IoUnexpectedEof IoTimedOut IoOther BridgeBinding BridgeConflict BridgeMissing BridgeUncertain BridgeLimit BridgePermission BridgeRecoveryRequired BridgeCompleteOriginRecoveryUnavailable BridgeVerification BridgeSignerOriginUnavailable BridgeJournal BridgeAuthority BridgeWallet BridgeIpc FrameUnclassified FrameDeadline FrameEof FrameCredentialsMissing FrameCredentialsMismatch FrameAncillaryRejected FrameTruncated FramePeerNotLive FrameCurrentCheck FrameIo FrameLimit FrameInvalidFrame FrameInvalidBudget EngineDisclosureUnknown EngineDisclosureDenied EngineRecoveryRequired EngineIdempotencyConflict EngineRevisionConflict EngineDurableProposalConflict EngineDurableConstructionUnavailable EngineDurableProfileUnavailable EngineResourceExhausted EngineUnclassified PredicateDenied'.split())
HOST_RELAY_STAGES=frozenset('LifecycleCheck DeadlineCheck HostAbsent CoordinatorLifetime Signer1Lifetime Signer2Lifetime CoordinatorReceive NormalControl CompletedPairControl RetirementControl DownstreamValidation TargetSelection Signer1Send Signer2Send RetirementObservation NormalObservation Signer1Receive Signer2Receive Signer1UpstreamValidation Signer2UpstreamValidation CoordinatorSend FinalLifecycleCheck'.split())
HOST_RELAY_CLASSES=frozenset('IoNotFound IoPermissionDenied IoInterrupted IoWouldBlock IoInvalidInput IoInvalidData IoUnexpectedEof IoTimedOut IoOther'.split())
def validate_host_relay_facts(facts):
    exact(facts,('stage','class'))
    require(type(facts['stage']) is str and facts['stage'] in HOST_RELAY_STAGES,'record_shape')
    require(type(facts['class']) is str and facts['class'] in HOST_RELAY_CLASSES,'record_shape')
    return facts

def validate_host_reap_facts(facts):
    exact(facts,('version','context','exit_code','signal'))
    require(type(facts['version']) is int and facts['version']==1,'record_shape')
    require(type(facts['context']) is str and facts['context'] in HOST_REAP_CONTEXTS,'record_shape')
    code,signal=facts['exit_code'],facts['signal']
    require((integer(code,0,255) and signal is None) or (code is None and integer(signal,1,64)),'record_shape')
    return facts

def validate_host_failure_facts(facts):
    exact(facts,('version','stage','class','relay'))
    require(type(facts['version']) is int and facts['version']==1,'record_shape')
    require(type(facts['stage']) is str and facts['stage'] in HOST_FAILURE_STAGES,'record_shape')
    require(type(facts['class']) is str and facts['class'] in HOST_FAILURE_CLASSES,'record_shape')
    if facts['relay'] is not None:validate_host_relay_facts(facts['relay'])
    return facts

def validate_host_exit_cardinality(records):
    # Record shapes, authenticated lineage and actor sequence are validated by
    # the enclosing collection/oracle; this imposes independent max-one caps
    # and consistency only when the existing owned-reap proof is also present.
    for kind in ('HostReapObservation','HostFailureBoundary'):
        require(sum(r['kind']==kind for r in records)<=1,'replay')
    observations=[r['facts'] for r in records if r['kind']=='HostReapObservation']
    if observations:
        observation=observations[0]
        for record in records:
            if record['kind']=='OwnedReap' and record['role']=='Coordinator' and record['facts']['child']=='Host':
                require(observation['signal'] is None and observation['exit_code']==record['facts']['exit_code'],'replay')

def unavailable_host_exit_diagnostic():
    return dict(version=1,reap=dict(availability='Unavailable',context=None,exit_code=None,signal=None),
                foreground=dict(availability='Unavailable',stage=None,relay=None,**{'class':None}))

def validate_host_exit_diagnostic(value):
    exact(value,('version','reap','foreground'))
    require(type(value['version']) is int and value['version']==1,'record_shape')
    for name,fields,validator in (('reap',('context','exit_code','signal'),validate_host_reap_facts),
                                  ('foreground',('stage','class','relay'),validate_host_failure_facts)):
        part=value[name];exact(part,('availability',)+fields)
        require(part['availability'] in ('Observed','Unavailable'),'record_shape')
        if part['availability']=='Unavailable':require(all(part[k] is None for k in fields),'record_shape')
        else:validator(dict(version=1,**{k:part[k] for k in fields}))
    return value


# Actor-local failure slots and actual owned reaps; no cross-actor chronology.
ACTOR_DRIVER_STAGES=frozenset(('Initialization', 'OriginalActors', 'Receive', 'Handle', 'Opening', 'PairBegin', 'PairPoll', 'EnrollmentBegin', 'ReceiptPoll', 'RedisclosurePoll', 'StatusPoll', 'DeliveryPoll', 'FinancialPoll', 'FinancialTransport', 'SourceRetention', 'WorkUnclassified', 'Cleanup', 'DisposalSend', 'EnrollmentPairingCheck', 'EnrollmentSessionCheck', 'EnrollmentPeerCheck', 'ManifestPairingCheck', 'ManifestSessionCheck', 'ManifestPeerCheck', 'PreconstructionCheck', 'WitnessWork', 'LeafProtocol', 'NormalDispose', 'AdmitReadAction', 'AdmitReadCurrent', 'AdmitReadDisplay', 'AdmitReadFinishCurrent', 'AdmitReadFinishCustody', 'AdmitReadFinishPhase', 'AdmitReadHistory', 'AdmitReadHistoryBounds', 'AdmitReadHistoryCallback', 'AdmitReadHistoryCallerDeadline', 'AdmitReadHistoryDigest', 'AdmitReadHistoryDisclosure', 'AdmitReadHistoryEventReplay', 'AdmitReadHistoryExchangeDeadline', 'AdmitReadHistoryFinalValidation', 'AdmitReadHistoryPageConnect', 'AdmitReadHistoryPageHandshake', 'AdmitReadHistoryPagePeerBinding', 'AdmitReadHistoryPageRequestBuild', 'AdmitReadHistoryPageRequestWrite', 'AdmitReadHistoryPageResponse', 'AdmitReadHistoryPageResponseRead', 'AdmitReadHistoryPageValidation', 'AdmitReadHistorySnapshotConnect', 'AdmitReadHistorySnapshotHandshake', 'AdmitReadHistorySnapshotPeerBinding', 'AdmitReadHistorySnapshotRequestBuild', 'AdmitReadHistorySnapshotRequestWrite', 'AdmitReadHistorySnapshotResponse', 'AdmitReadHistorySnapshotResponseRead', 'AdmitReadHistorySnapshotValidation', 'AdmitReadHistorySourceCallback', 'AdmitReadIntentDigest', 'AdmitReadPrepareIntent', 'AdmitReadPreparedSource', 'AdmitReadReceivedBinding', 'AdmitReadReport', 'AdmitReadRequestDigest', 'AdmitReadSourceAcquire', 'AdmitReadSourceAction', 'AdmitReadSourceAfter', 'AdmitReadSourceBefore', 'AdmitReadSourceBinding', 'AdmitReadSourceCallback', 'AdmitReadSourceCurrent', 'AdmitReadSourceLeasePermission', 'AdmitReadSourcePresentation', 'AdmitReadSourcePurpose', 'AdmitReadSourceRecords', 'AdmitReadSourceRetained', 'AdmitReadSourceRevision', 'AdmitReadSourceRevisionMissing', 'AdmitReadWitnessAction', 'AdmitReadWitnessBinding', 'AdmitReadWitnessCheck', 'AdmitReadWitnessCustody', 'AdmitReadWitnessDigest', 'AdmitReadWitnessPresentation', 'AdmitReadIntentAction', 'AdmitReadIntentAuthorityRequest', 'AdmitReadIntentCurrentRows', 'AdmitReadIntentFinancialRows', 'AdmitReadIntentHistoryDigest', 'AdmitReadIntentJournalAccount', 'AdmitReadIntentJournalIdentity', 'AdmitReadIntentJournalSchema', 'AdmitReadIntentOriginalRows', 'AdmitReadIntentReadPresentation', 'AdmitReadIntentReview', 'AdmitReadIntentReviewBinding', 'AdmitReadIntentReviewCeilings', 'AdmitReadIntentReviewDigest', 'AdmitReadIntentReviewMaterial', 'AdmitReadIntentReviewNested', 'AdmitReadIntentReviewShape', 'AdmitReadIntentRowsAccountUse', 'AdmitReadIntentRowsCurrentDisclosure', 'AdmitReadIntentRowsMaterial', 'AdmitReadIntentRowsOriginalDisclosure', 'AdmitReadIntentRowsOriginalLinks', 'AdmitReadIntentRowsSession', 'AdmitReadIntentRowsTransport', 'AdmitReadIntentScope', 'AdmitReadIntentSourceJournal', 'AdmitReadScopeAcquire', 'AdmitReadScopeClaims', 'AdmitReadScopeFixedInputs', 'AdmitReadScopeHistory', 'AdmitReadScopeOriginal', 'AdmitReadScopePermission', 'AdmitReadScopePolicy', 'AdmitReadScopePolicyBinding', 'AdmitReadScopePolicyExport', 'AdmitReadScopePolicyReturns', 'AdmitReadScopeRecipient', 'AdmitReadScopeTerms'))
ACTOR_LISTENER_STAGES=frozenset(('BoundsSource', 'BoundsHost', 'BoundsStopped', 'BoundsDeadline', 'PeerPairLifetime', 'PeerProcess', 'PeerRevoked', 'PeerDeadline', 'Accept', 'ReadTimeout', 'WriteTimeout', 'EnableCredentials', 'ObservePeer', 'OriginalHost', 'RequestRead', 'RequestDecode', 'Mode', 'GrantId', 'TokenDigest', 'GrantLock', 'GrantMissing', 'GrantCurrent', 'GrantPeer', 'TokenMismatch', 'RequestValidate', 'StatusRepeated', 'StatusNotProved', 'StatusEnqueue', 'StatusWrite', 'PairRepeated', 'PairScope', 'PairLabel', 'PairEnqueue', 'RequestEnqueue', 'RequestKind', 'StreamClone', 'WorkUnclassified'))
ACTOR_ORIGIN_STAGES=frozenset(('PeerProcessExit', 'PeerProcessPollError', 'PeerEdgeClosed', 'PeerEdgePollError', 'RootProcessExit', 'RootProcessPollError', 'ActorCustody', 'ActorClosed', 'SessionDeadline', 'ActionRevoked', 'ActionQuiescent', 'ActionClosing', 'SharedRestriction', 'SharedRestrictionCustody', 'SharedRestrictionDeadline', 'SharedWallDeadline', 'SharedWallRead', 'SharedWallRollback', 'SourceWallSample', 'SourceLifetime', 'SourceAction', 'PairWallSample', 'PairChannel', 'PairAction', 'PairPhase', 'WitnessReceive', 'WitnessWork', 'LeafStop', 'LeafExit', 'ChildBootstrap', 'WitnessCheck', 'NormalHandshake', 'SourceDeadline', 'ReviewDeadline', 'AcceptedDeadline', 'ReadDeadline', 'ServiceDeadline', 'BoundDeadline'))
ACTOR_CLASSES=frozenset(('IoNotFound', 'IoPermissionDenied', 'IoInterrupted', 'IoWouldBlock', 'IoInvalidInput', 'IoInvalidData', 'IoUnexpectedEof', 'IoTimedOut', 'IoOther', 'SignerUnavailable', 'SignerPeerLifetimeUnavailable', 'SignerAuthentication', 'SignerInvalidData', 'SignerCrypto', 'SignerLocked', 'SignerBackupRequired', 'SignerRecoveryRequired', 'SignerAlreadyOpen', 'SignerReviewMismatch', 'SignerVerification', 'SignerUncertain', 'SignerConsentJournal', 'SignerStore', 'BridgeBinding', 'BridgeConflict', 'BridgeMissing', 'BridgeUncertain', 'BridgeLimit', 'BridgePermission', 'BridgeRecoveryRequired', 'BridgeCompleteOriginRecoveryUnavailable', 'BridgeVerification', 'BridgeSignerOriginUnavailable', 'BridgeJournal', 'BridgeAuthority', 'BridgeWallet', 'BridgeIpc', 'FrameUnclassified', 'FrameDeadline', 'FrameEof', 'FrameCredentialsMissing', 'FrameCredentialsMismatch', 'FrameAncillaryRejected', 'FrameTruncated', 'FramePeerNotLive', 'FrameCurrentCheck', 'FrameIo', 'FrameLimit', 'FrameInvalidFrame', 'FrameInvalidBudget', 'PredicateDenied', 'ClockExpired', 'WallRollback', 'Restricted', 'Quiescent', 'Closing', 'ProcessExited', 'ProcessPollError', 'EdgeClosed', 'EdgePollError', 'CustodyMismatch', 'AlreadyClosed', 'JournalStorage', 'JournalDatabase', 'JournalPermission', 'JournalExpired', 'JournalRecoveryRequired', 'JournalUnsupportedSchema', 'JournalOfflineHistoryUnsupported', 'JournalNamedRecipientHistoryUnsupported', 'JournalConstructionHistoryUnsupported', 'JournalInvalidBinding', 'JournalConflict', 'JournalNotFound', 'JournalLiveAuthorization', 'JournalInputReserved', 'JournalBudgetExceeded', 'JournalLimit', 'IoConnectionRefused', 'AuthorityInvalidBinding', 'AuthorityPermission', 'AuthorityStaleHead', 'AuthorityConflict', 'AuthorityInactive', 'AuthorityRecoveryRequired', 'AuthorityExpired', 'AuthorityPolicyDenied', 'AuthorityBudgetExceeded', 'AuthorityInputReserved', 'AuthorityObligationReserved', 'AuthorityLimit', 'AuthorityStorage', 'AuthorityCorruptHistory', 'AuthorityPermanentStopUnavailable', 'AuthorityOfflineHistoryUnsupported', 'AuthorityConstructionHistoryUnsupported', 'AuthorityUnsupportedVersion', 'AuthorityAuthentication', 'AuthorityUncertain', 'AuthorityResolutionUnavailable', 'AuthoritySessionRequired', 'AuthoritySessionPending'))
ACTOR_ROLES=frozenset(('Coordinator', 'Host', 'Signer1', 'Signer2', 'Owner1BootstrapHistory', 'Owner1V3DeliveryAdmission', 'Owner1DeliveryAuditHistory', 'Owner1FinancialReadHistory', 'Owner1FinancialContinuationAdmission', 'Owner1FinancialSigning', 'Owner2BootstrapHistory', 'Owner2V3DeliveryAdmission', 'Owner2DeliveryAuditHistory', 'Owner2FinancialReadHistory', 'Owner2FinancialContinuationAdmission', 'Owner2FinancialSigning', 'CompletedPair'))
ACTOR_REAP_OWNERS={'Coordinator': ('Host', 'Owner1BootstrapHistory', 'Owner1V3DeliveryAdmission', 'Owner1DeliveryAuditHistory', 'Owner1FinancialReadHistory', 'Owner1FinancialContinuationAdmission', 'Owner1FinancialSigning', 'Owner2BootstrapHistory', 'Owner2V3DeliveryAdmission', 'Owner2DeliveryAuditHistory', 'Owner2FinancialReadHistory', 'Owner2FinancialContinuationAdmission', 'Owner2FinancialSigning', 'CompletedPair'), 'Host': ('Signer1', 'Signer2')}
def validate_actor_failure_facts(facts,role=None):
    exact(facts,('version','driver','listener','origin'))
    require(type(facts['version']) is int and facts['version']==1,'record_shape')
    require(facts['driver'] is not None,'record_shape')
    if role is not None:require(role in ('Signer1','Signer2') or facts['listener'] is None,'role')
    for slot,stages in (('driver',ACTOR_DRIVER_STAGES),('listener',ACTOR_LISTENER_STAGES),('origin',ACTOR_ORIGIN_STAGES)):
        part=facts[slot]
        if part is None:continue
        exact(part,('stage','class','peer') if slot=='origin' else ('stage','class'))
        require(type(part['stage']) is str and part['stage'] in stages,'record_shape')
        require(type(part['class']) is str and part['class'] in ACTOR_CLASSES,'record_shape')
        if slot=='origin':require(part['peer'] is None or (type(part['peer']) is str and part['peer'] in ACTOR_ROLES),'record_shape')
    return facts

def validate_actor_reap_facts(facts,parent):
    exact(facts,('version','child','context','exit_code','signal'))
    require(type(facts['child']) is str and facts['child'] in ACTOR_REAP_OWNERS.get(parent,()),'role')
    validate_host_reap_facts({k:facts[k] for k in ('version','context','exit_code','signal')})
    return facts

def validate_actor_cardinality(records):
    failures=set();reaps={}
    for r in records:
        if r['kind']=='ActorFailureBoundary':
            require(r['role'] not in failures,'replay');failures.add(r['role'])
        elif r['kind']=='ActorReapObservation':
            f=r['facts'];child=f['child'];require(child not in reaps,'replay');reaps[child]=(r['role'],f)
    for child,(parent,f) in reaps.items():
        for r in records:
            if r['kind']=='OwnedReap' and r['role']==parent and r['facts']['child']==child:
                require(f['signal'] is None and f['exit_code']==r['facts']['exit_code'],'replay')
            if child=='Host' and r['kind']=='HostReapObservation':
                require(all(f[k]==r['facts'][k] for k in ('context','exit_code','signal')),'replay')

def unavailable_actor_diagnostic():
    # Explicit null means unavailable, never absence of a failure. Fixed slots.
    return dict(version=1,actors={role:dict(failure=None,reap=None) for role in sorted(ACTOR_ROLES)})

def validate_actor_diagnostic(value):
    exact(value,('version','actors'));require(type(value['version']) is int and value['version']==1,'record_shape')
    exact(value['actors'],ACTOR_ROLES)
    for role,parts in value['actors'].items():
        exact(parts,('failure','reap'))
        f=parts['failure']
        if f is not None:
            exact(f,('driver','listener','origin'));validate_actor_failure_facts(dict(version=1,**f),role)
        reap=parts['reap']
        if reap is not None:
            exact(reap,('parent','context','exit_code','signal'))
            require(type(reap['parent']) is str,'role')
            validate_actor_reap_facts(dict(version=1,child=role,**{k:reap[k] for k in ('context','exit_code','signal')}),reap['parent'])
    require(len(json.dumps(value,separators=(',',':')).encode())<=8000,'record_limit')
    return value

# CI-only, Coordinator-local failure boundaries. These are neither milestones
# nor a cross-process ordering/root-cause claim. The native emission gate is
# an actual Ui/Driver failure; Core/Transport observations alone cannot emit.
NATIVE_FAILURE_COMPONENTS=('ui','driver','transport','core')
NATIVE_FAILURE_CODES={
    'ui':frozenset(('Unobserved', 'ViewportMissing', 'FocusLost', 'Blur', 'Escape', 'CloseRequested', 'InputGuardRejected', 'ObserverRejected', 'DriverRestrictionObserved', 'NativeCheckRejected', 'FinishedObserved', 'HostTransportRejected', 'HostOutputRejected', 'HostContextChanged', 'PublicInputRejected', 'NormalProofRejected', 'OtherUiRestriction')),
    'driver':frozenset(('Unobserved', 'OriginalTreeCheckError', 'SessionExpired', 'EndpointRestrictionObserved', 'CommandChannelDisconnected', 'CommandOperationError', 'CancelSendError', 'SourceReceiveError', 'HistoryReceiveError', 'SigningReceiveError', 'PairReceiveError', 'OutcomeChannelFull', 'OutcomeChannelDisconnected', 'WorkErrorUnclassified')),
    'transport':frozenset(('Unobserved', 'RestrictedObserved', 'InputChannelDisconnected', 'QueueInputRejected', 'StatusFull', 'StatusDisconnected', 'OutputChannelDisconnected', 'CoreCheckRejected', 'PtyOutputEof', 'PtyReadError', 'PtyWriteError', 'PtyOwnerMismatch', 'PtyHostLifetimeLost', 'PtyModeRejected')),
    'core':frozenset(('Unobserved', 'CustodyMismatch', 'AlreadyClosedObserved', 'PeerProcessExit', 'PeerProcessPollError', 'PeerEdgeClosed', 'PeerEdgePollError', 'RootProcessExit', 'RootProcessPollError', 'SessionExpired')),
}

def validate_native_failure_facts(facts):
    exact(facts,('version',)+NATIVE_FAILURE_COMPONENTS)
    require(type(facts['version']) is int and facts['version']==1,'record_shape')
    for name in NATIVE_FAILURE_COMPONENTS:
        require(type(facts[name]) is str and facts[name] in NATIVE_FAILURE_CODES[name],'record_shape')
    require(facts['ui']!='Unobserved' or facts['driver']!='Unobserved','record_shape')
    return facts

def native_failure_sequence(records,expected_profile):
    """Validate cached per-process aggregates; return latest or None, never IO."""
    require(expected_profile in (PROFILE,EXTERNAL_PROFILE,SEMANTIC_PROFILE),'record_shape')
    require(type(records) is list and len(records)<=MAX_RECORDS,'record_limit')
    for record in records:validate_record(record,expected_profile)
    return _native_failure_sequence_validated(records)

def _native_failure_sequence_validated(records):
    # Private aggregate over this read's fully validated, bounded batch only.
    rows=[r for r in records if r['role']=='Coordinator']
    boundaries=[r for r in rows if r['kind']=='NativeFailureBoundary']
    if not boundaries:return None
    require(len(boundaries)<=4,'record_limit')
    rows.sort(key=lambda r:r['sequence'])
    require([r['sequence'] for r in rows]==list(range(1,len(rows)+1)),'order')
    require(rows[0]['kind']=='Birth' and sum(r['kind']=='Birth' for r in rows)==1,'lineage')
    require(all(a['elapsed_ns']<=b['elapsed_ns'] for a,b in zip(rows,rows[1:])),'order')
    prior={name:'Unobserved' for name in NATIVE_FAILURE_COMPONENTS};latest=None
    for record in rows:
        if record['kind']!='NativeFailureBoundary':continue
        facts=record['facts']
        require(any(facts[name]!=prior[name] for name in NATIVE_FAILURE_COMPONENTS),'replay')
        require(all(prior[name]=='Unobserved' or facts[name]==prior[name] for name in NATIVE_FAILURE_COMPONENTS),'replay')
        prior={name:facts[name] for name in NATIVE_FAILURE_COMPONENTS};latest=dict(facts)
    return latest

def validate_native_failure_diagnostic(value):
    exact(value,('version','availability')+NATIVE_FAILURE_COMPONENTS)
    require(type(value['version']) is int and value['version']==1,'record_shape')
    require(value['availability'] in ('Observed','Unavailable'),'record_shape')
    for name in NATIVE_FAILURE_COMPONENTS:
        require(type(value[name]) is str and value[name] in NATIVE_FAILURE_CODES[name],'record_shape')
    if value['availability']=='Observed':
        validate_native_failure_facts({k:v for k,v in value.items() if k!='availability'})
    else:require(all(value[name]=='Unobserved' for name in NATIVE_FAILURE_COMPONENTS),'record_shape')
    return value

def cached_native_failure_diagnostic(records,expected_profile):
    require(expected_profile==SEMANTIC_PROFILE,'record_shape')
    facts=native_failure_sequence(records,expected_profile)
    value=dict(version=1,availability='Unavailable',**{name:'Unobserved' for name in NATIVE_FAILURE_COMPONENTS})
    if facts is not None:value.update(facts,availability='Observed')
    return validate_native_failure_diagnostic(value)

# Failure-only diagnostic, not oracle evidence. Array order is fixed by these
# tuples; 2 means at least two observations, never two successful operations.
# Missing counts describe the last cached observation only, not nonexecution.
# Phase counts are frame observations only: no order, duration or cause.
DIAGNOSTIC_PHASES=tuple(sorted(PHASES))
NORMAL_DIAGNOSTIC_STEPS=('NormalFinishAdmitted','PtyHeld','PtyReleased','NormalFinished')

def validate_progress_diagnostic(value):
    exact(value,('version','signer_counts','host_counts','normal_counts','phase_counts'))
    require(type(value['version']) is int and value['version']==1,'record_shape')
    rows=value['signer_counts']
    require(type(rows) is list and len(rows)==2,'record_shape')
    for row,size in [(rows[0],len(SIGNER_STEPS)),(rows[1],len(SIGNER_STEPS)),
                     (value['host_counts'],len(HOST_STEPS)),
                     (value['normal_counts'],len(NORMAL_DIAGNOSTIC_STEPS)),
                     (value['phase_counts'],len(DIAGNOSTIC_PHASES))]:
        require(type(row) is list and len(row)==size and
                all(type(count) is int and 0<=count<=2 for count in row),'record_shape')
    return value

def cached_progress_diagnostic(records,expected_profile):
    """Project only validated cached records; no reads, waits or clock changes."""
    require(expected_profile in (PROFILE,EXTERNAL_PROFILE,SEMANTIC_PROFILE),'record_shape')
    require(type(records) is list and len(records)<=MAX_RECORDS,'record_limit')
    value={'version':1,'signer_counts':[[0]*len(SIGNER_STEPS) for _ in range(2)],
           'host_counts':[0]*len(HOST_STEPS),'normal_counts':[0]*len(NORMAL_DIAGNOSTIC_STEPS),
           'phase_counts':[0]*len(DIAGNOSTIC_PHASES)}
    for record in records:
        validate_record(record,expected_profile)
        kind,facts=record['kind'],record['facts']
        if kind=='SignerMilestone':
            row=value['signer_counts'][('Signer1','Signer2').index(facts['owner'])]
            index=SIGNER_STEPS.index(facts['step'])
        elif kind=='HostMilestone':
            row=value['host_counts'];index=HOST_STEPS.index(facts['step'])
        elif kind=='UiSnapshot':
            row=value['phase_counts'];index=DIAGNOSTIC_PHASES.index(facts['phase'])
        elif kind in NORMAL_DIAGNOSTIC_STEPS:
            row=value['normal_counts'];index=NORMAL_DIAGNOSTIC_STEPS.index(kind)
        else:continue
        row[index]=min(2,row[index]+1)
    return validate_progress_diagnostic(value)

# Cached actor-local observation timing, never current time or authority evidence.
def validate_observation_timing_diagnostic(value):
    exact(value,('version','availability','observer_remaining_ns','coordinator_last_elapsed_ns','last_phase','phase_observed_ns_counts','coordinator_milestone_elapsed_ns'))
    require(type(value['version']) is int and value['version']==2,'record_shape')
    require(value['availability'] in ('Observed','Unavailable'),'record_shape')
    remaining=value['observer_remaining_ns'];last=value['coordinator_last_elapsed_ns'];phase=value['last_phase']
    if value['availability']=='Unavailable':
        require(remaining is None and last is None and phase is None and value['phase_observed_ns_counts'] is None and value['coordinator_milestone_elapsed_ns'] is None,'record_shape');return value
    require(integer(remaining,1,ORIGINAL_NS),'record_shape')
    require(last is None or integer(last,0,ORIGINAL_NS),'record_shape')
    # Fixed owner rows None/Signer1/Signer2 and DIAGNOSTIC_PHASES columns.
    # Each cell is [sum of observed contiguous same phase/subphase spans, count].
    rows=value['phase_observed_ns_counts']
    require(type(rows) is list and len(rows)==3,'record_shape')
    total=0;observed_ns=0
    for row in rows:
        require(type(row) is list and len(row)==len(DIAGNOSTIC_PHASES),'record_shape')
        for cell in row:
            require(type(cell) is list and len(cell)==2 and integer(cell[0],0,ORIGINAL_NS) and integer(cell[1],0,MAX_RECORDS),'record_shape')
            require(cell[1]>0 or cell[0]==0,'record_shape');total+=cell[1];observed_ns+=cell[0]
    require(total<=MAX_RECORDS and (last is not None or total==0) and observed_ns<=(last or 0),'record_shape')
    offsets=value['coordinator_milestone_elapsed_ns']
    require(type(offsets) is list and len(offsets)==2,'record_shape')
    for row in offsets:
        require(type(row) is list and len(row)==len(SIGNER_STEPS),'record_shape')
        require(all(x is None or (last is not None and integer(x,0,last)) for x in row),'record_shape')
    if phase is not None:
        exact(phase,('phase','subphase','owner','first_elapsed_ns','last_elapsed_ns','snapshot_count'))
        require(type(phase['phase']) is str and phase['phase'] in PHASES and type(phase['subphase']) is str and phase['subphase'] in SUBPHASES and phase['owner'] in (None,'Signer1','Signer2'),'record_shape')
        require(last is not None and integer(phase['first_elapsed_ns'],0,last) and
                integer(phase['last_elapsed_ns'],phase['first_elapsed_ns'],last) and
                integer(phase['snapshot_count'],1,MAX_RECORDS),'record_shape')
    return value

# Failure-only harness observations, never native milestones or success evidence.
HOST_DIAGNOSTIC_CATEGORIES=frozenset(('none','tail_not_visible','capture_guard','host_context','host_capture_changed','host_capture_count','host_capture_grammar','host_occurrence_replay','host_entry_changed','host_capture_limit'))
HOST_DIAGNOSTIC_STAGES=frozenset(('Unobserved','Profile','Workspace','Storage','Financial','Enrollment','Commands','Operational','Approval'))
HOST_DIAGNOSTIC_ACTIONS=frozenset(('Unobserved','NoPending','BeginRequested','BeginReturned','TypingRequested','TypingReturned','SubmitRequested','SubmitReturned'))
HOST_DIAGNOSTIC_ENTRIES=frozenset(('Unobserved','Idle','Editing','Writing','Closed'))
HOST_DIAGNOSTIC_COVERAGE=frozenset(('Unobserved','Unavailable','TailSuffix','WholeRetained'))
def validate_host_diagnostic(value):
    require(type(value) is dict and type(value.get('version')) is int and value['version'] in (1,2))
    keys=('version','category','startup_stage','attempted_lines')
    exact(value,keys if value['version']==1 else (*keys,'boundary','observation'))
    require(type(value['category']) is str and value['category'] in HOST_DIAGNOSTIC_CATEGORIES)
    require(type(value['startup_stage']) is str and value['startup_stage'] in HOST_DIAGNOSTIC_STAGES)
    require(integer(value['attempted_lines'],0,128))
    if value['version']==2:
        b=value['boundary'];o=value['observation']
        exact(b,('action','startup_index','issued_index','pending_index','pending_host','input_attempted','waiting'))
        exact(o,('entry','context_valid','pending_context','coverage','capture_outcome','capture_context'))
        require(type(b['action']) is str and b['action'] in HOST_DIAGNOSTIC_ACTIONS)
        require(integer(b['startup_index'],0,13) and integer(b['issued_index'],-1,12) and integer(b['pending_index'],-1,12))
        require(all(type(b[k]) is bool for k in ('pending_host','input_attempted','waiting')))
        require(type(o['entry']) is str and o['entry'] in HOST_DIAGNOSTIC_ENTRIES)
        require(o['context_valid'] is None if o['entry']=='Unobserved' else type(o['context_valid']) is bool)
        require(type(o['pending_context']) is str and o['pending_context'] in ('Unobserved','NoPending','Same','Changed'))
        require(type(o['coverage']) is str and o['coverage'] in HOST_DIAGNOSTIC_COVERAGE)
        require(type(o['capture_outcome']) is str and o['capture_outcome'] in (HOST_DIAGNOSTIC_CATEGORIES|{'Unobserved','Accepted'}))
        require(type(o['capture_context']) is str and o['capture_context'] in ('Unobserved','Same','Changed'))
    return value


# Failure-only Python guard attribution; never native authority or success proof.
INPUT_BUDGET_LIMITS={'actions':512,'scroll':128,'idle_sweep':64,'paired_review':256,
 'challenges':96,'host_tail':128,'host_coverage':128,'host_lines':128,'startup_focus':64,
 'fixture_preflight':MAX_NATIVE_COMMANDS}
INPUT_WIDGET_TAGS=tuple(sorted(WIDGETS))
def input_budget(ok,site,count):
    if not ok:
        error=Rejected('input_budget')
        try:error.input_budget={'site':site,'count':count,'limit':INPUT_BUDGET_LIMITS[site]}
        except Exception:pass  # Attribution must not replace the original rejection.
        raise error

def validate_input_diagnostic(value):
    exact(value,('version','budget','last_main_loop'))
    require(type(value['version']) is int and value['version']==1)
    b=value['budget'];exact(b,('site','count','limit'))
    require(type(b['site']) is str and b['site'] in INPUT_BUDGET_LIMITS)
    require(type(b['limit']) is int and b['limit']==INPUT_BUDGET_LIMITS[b['site']])
    require(integer(b['count'],b['limit']+int(b['site'] in ('actions','host_lines','fixture_preflight')),1<<30))
    s=value['last_main_loop']
    if s is not None:
        exact(s,('phase','subphase','owner','target','widget_states'))
        require(type(s['phase']) is str and s['phase'] in PHASES and type(s['subphase']) is str and s['subphase'] in SUBPHASES)
        require(s['owner'] in (None,'Signer1','Signer2') and s['target'] in (None,'Signer1','Signer2'))
        rows=s['widget_states']
        # Rows: None, Signer1, Signer2. Columns: INPUT_WIDGET_TAGS.
        # 0 absent, 1 disabled, 2 enabled; 3/4 disabled/enabled + default-ordinal latch; 5 absent + default-ordinal latch.
        require(type(rows) is list and len(rows)==3)
        for row in rows:
            require(type(row) is list and len(row)==len(INPUT_WIDGET_TAGS))
            require(all(integer(v,0,5) for v in row))
    return value


# Failure-only last validated controller review observation, never native authority.
def validate_review_diagnostic(value):
    exact(value,('version','semantics','phase','subphase','owner','generation','widgets','seek_counts',
                 'scroll_counts','attempted','owed_wheel','last_seek','operation','boundary','operation_generation','anchor','point_inside'))
    require(type(value['version']) is int and value['version']==1)
    require(value['semantics']=='LastValidatedReview' and value['phase']=='V3AdmitReview' and value['subphase']=='None')
    require(value['owner'] in ('Signer1','Signer2') and integer(value['generation'],1))
    ws=value['widgets'];require(type(ws) is list and len(ws)==3)
    for pair in ws:
        require(type(pair) is list and len(pair)==2 and all(type(v) is bool for v in pair) and (pair[0] or not pair[1]))
    for key,limit in (('seek_counts',65),('scroll_counts',128)):
        a=value[key];require(type(a) is list and len(a)==3 and all(integer(v,0,limit) for v in a))
    require(type(value['attempted']) is list and len(value['attempted'])==2 and all(type(v) is bool for v in value['attempted']))
    require(type(value['owed_wheel']) is bool)
    require(value['last_seek'] in ('None','Body','Ack','Arm'))
    require(value['operation'] in ('None','AckPress','ArmPress','OtherPress','BodyDown','OuterUp','OuterDown','OtherScroll'))
    require(value['boundary'] in ('None','Requested','Returned') and value['anchor'] in ('None','Body','Outer','Ack','Arm'))
    require(value['point_inside'] is None or type(value['point_inside']) is bool)
    require((value['operation']=='None')==(value['boundary']=='None'))
    require(value['operation_generation'] is None if value['operation']=='None' else integer(value['operation_generation'],1,value['generation']))
    expected_anchor={'None':'None','AckPress':'Ack','ArmPress':'Arm','OtherPress':'None','BodyDown':'Body','OuterUp':'Outer','OuterDown':'Outer','OtherScroll':'None'}
    require(value['anchor']==expected_anchor[value['operation']])
    require(value['point_inside'] is None if value['anchor']=='None' else type(value['point_inside']) is bool)
    require(len(json.dumps(value,separators=(',',':')).encode())<=2048)
    return value
