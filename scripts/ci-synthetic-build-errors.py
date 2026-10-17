#!/usr/bin/env python3
"""Public-only Rust failure locations. Never emit rendered diagnostics or text."""
import json
import pathlib
import re
import subprocess
import sys

MAX_LINE = 2 * 1024 * 1024
MAX_BYTES = 64 * 1024 * 1024
MAX_LOCATIONS = 20
SOURCE = re.compile(r"crates/[A-Za-z0-9_-]+/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.rs")
CODE = re.compile(r"E[0-9]{4}")

def public_sources(root):
    result=subprocess.run(['git','-C',str(root),'ls-files','-z','--','crates'],
                          capture_output=True,timeout=10,check=True)
    if result.stderr or len(result.stdout)>2*1024*1024:
        raise ValueError('public source inventory unavailable')
    return frozenset(name for name in result.stdout.decode('utf8').split('\0')
                     if SOURCE.fullmatch(name))

def project(row, sources, root):
    if not isinstance(row,dict) or row.get('reason')!='compiler-message': return []
    message=row.get('message')
    if not isinstance(message,dict) or message.get('level')!='error': return []
    detail=message.get('code')
    code=detail.get('code') if isinstance(detail,dict) else None
    if not isinstance(code,str) or not CODE.fullmatch(code): code='Uncoded'
    spans=message.get('spans')
    if not isinstance(spans,list): spans=[]
    output=[]
    for span in spans[:64]:
        if not isinstance(span,dict) or span.get('is_primary') is not True: continue
        name=span.get('file_name')
        if not isinstance(name,str) or len(name)>1024: continue
        prefix=str(root)+'/'
        if name.startswith(prefix): name=name[len(prefix):]
        if name not in sources or not SOURCE.fullmatch(name): continue
        first,last=span.get('line_start'),span.get('line_end')
        if type(first) is not int or type(last) is not int or not 1<=first<=last<=10_000_000: continue
        output.append({'code':code,'source':name,'line_start':first,'line_end':last})
        if len(output)==MAX_LOCATIONS: break
    if not output:
        output.append({'code':code,'source':None,'line_start':None,'line_end':None})
    return output

def scan(stream, sources, root):
    locations=[]; seen=set(); total=0; discarding=False; truncated=False
    while total<MAX_BYTES:
        raw=stream.readline(min(MAX_LINE+1,MAX_BYTES-total))
        if not raw: break
        total+=len(raw)
        complete=raw.endswith(b'\n')
        if discarding or len(raw)>MAX_LINE:
            discarding=not complete; truncated=True; continue
        if not complete and total>=MAX_BYTES:
            truncated=True; break
        try: row=json.loads(raw)
        except (ValueError,UnicodeDecodeError): continue
        for item in project(row,sources,root):
            key=(item['code'],item['source'],item['line_start'],item['line_end'])
            if key in seen: continue
            seen.add(key); locations.append(item)
            if len(locations)==MAX_LOCATIONS:
                return locations,True
    if total>=MAX_BYTES: truncated=True
    return locations,truncated

def main():
    if len(sys.argv)!=3 or sys.argv[2] not in ('host','signer'): raise ValueError('invalid phase')
    root=pathlib.Path(__file__).resolve().parent.parent
    sources=public_sources(root)
    with open(sys.argv[1],'rb') as stream:
        locations,truncated=scan(stream,sources,root)
    for item in locations:
        print('CI_SYNTHETIC_COMPILER_ERROR '+json.dumps(dict(phase=sys.argv[2],**item),separators=(',',':'),sort_keys=True),flush=True)
    print('CI_SYNTHETIC_COMPILER_SUMMARY '+json.dumps({'phase':sys.argv[2],'locations':len(locations),'truncated':truncated,'raw_diagnostics_withheld':True},separators=(',',':'),sort_keys=True),flush=True)

if __name__=='__main__':
    try: main()
    except Exception:
        print('CI_SYNTHETIC_COMPILER_SUMMARY projection_unavailable=true raw_diagnostics_withheld=true',flush=True)
        sys.exit(1)
