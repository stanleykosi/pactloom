"""Bounded content-free Host crop binding. No native readiness or authority claim."""
import re
ASCII_WS = ' \t\r\n\f\v'
class HostContextRejected(Exception):
    def __init__(self, code):
        self.code=code if code in CATEGORIES else 'host_context'
        super().__init__(self.code)
CATEGORIES=frozenset(('host_context','host_capture_changed','host_capture_count','host_capture_grammar','host_occurrence_replay','host_entry_changed','host_capture_limit'))
def need(ok, code='host_context'):
    if not ok: raise HostContextRejected(code)
def count(text): return sum(c not in ASCII_WS for c in text)
PROMPTS = ['Existing original Host profile directory (absolute): ', 'Existing original dispatcher workspace directory (absolute): ', 'Storage passphrase: ', 'Original primary financial passphrase: ', 'Local application principal ID: ', 'Scope choice: type SELECTED for only exact agreement IDs (including any new IDs you intend to create), OWNED for all existing AND future agreements owned by this principal plus selected shared IDs, or ALL for every local agreement: ', 'Additional shared agreement IDs, comma-separated; blank for none: ', 'Exact selected agreement IDs, comma-separated; blank grants no agreements: ', 'Grant READ only, or PREPARE (read/propose/intent/coordinate/disclose; never signing/submission)? ', 'Optional exact browser origin for this session (for example http://127.0.0.1:4319); blank keeps native-app-only access: ', 'New private bootstrap credential file (absolute path; manually enter it only in the approved local application): ', 'Exact immutable command keys JSON file {version:1,bind_key,intake_keys:[first,second],completion_key} (absolute): ', 'Exact coordinated reviewer selection JSON {import_operation_id,redisclosure_operation_id,account_id,participant_id,choices}; source/receipt references are obtained from the actual originals: ', 'Exact copied native continuation selector JSON file (absolute): ', 'Exact copied native AwaitingReturn result selector JSON file (absolute): ']
def _literal_pattern(value):
    # Only visual whitespace BETWEEN native literal tokens may vary. No missing
    # character, altered punctuation, wrapped challenge, or payload is repaired.
    return re.escape(value.strip(ASCII_WS)).replace(r'\ ',r'[ \t\r\n\f\v]+')
PATTERNS=[re.compile(_literal_pattern(p)+r'[ \t\r\n\f\v]*\Z') for p in PROMPTS]
APPROVAL=re.compile(r'Type[ \t\r\n\f\v]+(APPROVE [0-9a-f]{16})[ \t\r\n\f\v]+to[ \t\r\n\f\v]+approve[ \t\r\n\f\v]+this[ \t\r\n\f\v]+exact[ \t\r\n\f\v]+operation,[ \t\r\n\f\v]+or[ \t\r\n\f\v]+anything[ \t\r\n\f\v]+else[ \t\r\n\f\v]+to[ \t\r\n\f\v]+reject:[ \t\r\n\f\v]*\Z')
class HostOccurrences:
    def __init__(self): self.frontier=0; self.attempts=0; self.last_revision=0; self.last_end=0
    def inspect(self,text,observation):
        h=observation; view=h['view']
        need(h['context_valid'] and h['entry']=='Idle' and view is not None)
        need(h['revision']>=self.last_revision and h['nonws_end']>=self.last_end)
        self.last_revision=h['revision'];self.last_end=h['nonws_end']
        need(type(text) is str and text.isascii() and len(text)<=8192,'host_capture_limit')
        need(count(text)==view['nonws'],'host_capture_count')
        matches=[m for p in (*PATTERNS,APPROVAL) if (m:=p.search(text)) is not None]
        need(len(matches)==1,'host_capture_grammar')
        m=matches[0]; size=count(m.group(0)); end=h['nonws_end']; start=end-size
        need(0<size<=view['nonws']<=end)
        need(start>=self.frontier and end>self.frontier,'host_occurrence_replay')
        return (start,end,h['revision']),m.group(0)
    def latch(self,occurrence):
        start,end,revision=occurrence
        need(start>=self.frontier and end>self.frontier,'host_occurrence_replay')
        need(self.attempts<128,'host_capture_limit')
        self.frontier=end; self.attempts+=1
    @staticmethod
    def editor_matches(occurrence,h):
        return (h['context_valid'] and h['entry']=='Editing' and h['editor'] is not None
                and h['revision']==occurrence[2]==h['editor']['revision']
                and h['nonws_end']==occurrence[1] and h['view'] is None)

STAGES=('Unobserved','Profile','Workspace','Storage','Financial','Enrollment','Commands','Operational','Approval')
def stage(suffix):
    for index,pattern in enumerate(PATTERNS):
        if pattern.fullmatch(suffix):
            if index<4:return STAGES[index+1]
            if index<11:return 'Enrollment'
            if index==11:return 'Commands'
            return 'Operational'
    return 'Approval' if APPROVAL.fullmatch(suffix) else 'Operational'

def clipped_prompt_tail(text):
    # Navigation hint ONLY. Even a one-character final wrapped row may be a
    # clipped prompt. This never authorizes a reply or repairs OCR. The caller
    # bounds coverage exploration and yields to Source for incidental endings.
    compact=''.join(c for c in text if c not in ASCII_WS)
    if not compact:return False
    width=min(16,len(compact))
    endings=[counted[-width:] for p in (*PROMPTS,'or anything else to reject:')
             if (counted:=''.join(c for c in p if c not in ASCII_WS))]
    return compact[-width:] in endings
