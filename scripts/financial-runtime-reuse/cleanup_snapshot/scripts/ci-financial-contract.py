#!/usr/bin/env python3
"""Closed full-financial CI contract. Import does not launch or approve anything."""
import json
import math

PROFILE = 'coordinated-financial-full-native-v1'
EXTERNAL_PROFILE = 'coordinated-financial-external-pre-v3-witness-v1'
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

def validate_snapshot(facts):
    exact(facts, ('phase','subphase','owner','view_generation','focused','secret_input','host_input',
                  'pixels_per_point','viewport','widgets'))
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
    return facts

def validate_record(record, expected_profile=PROFILE):
    require(expected_profile in (PROFILE,EXTERNAL_PROFILE))
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
        exact(facts, ()); require(expected_profile==EXTERNAL_PROFILE and role in INERT_WITNESSES,'role')
    elif kind == 'OwnedReap':
        exact(facts, ('child','pid','exit_code'))
        require(facts['child'] in PARENTS and PARENTS[facts['child']] == role and
                integer(facts['pid'],2,2**31-1) and integer(facts['exit_code'],0,255), 'lineage')
    elif kind in ('NormalFinishAdmitted','NormalFinished','PtyHeld','PtyReleased'):
        exact(facts, ()); require(role == 'Coordinator','role')
    elif kind == 'UiSnapshot':
        require(role == 'Coordinator','role'); validate_snapshot(facts)
    elif kind == 'Failure':
        exact(facts, ('code',)); require(facts['code'] in ERRORS,'record_shape')
    else:
        raise Rejected('record_shape')
    return record
