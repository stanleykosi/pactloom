"""Separate pre-runtime acquisition process. Token never enters archive/children.

This module creates no fixture, subprocess, container or native execution. It
follows the authenticated API's ZIP redirect WITHOUT an Authorization header.
No URLs, API bodies, exceptions or credential strings are printed.
"""
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Loading reviewed launcher code is normal; runtime safe_environment is NOT
# called here. This process alone receives the short-lived read token.
# L is injected only by the tracked launcher after source verification.

MAX_ARCHIVE=L.V.A.MAX_TOTAL+L.V.A.MAX_MANIFEST+1024*1024

# Failure-only fixed vocabulary: never expose response bodies or exceptions.
DIAGNOSTIC_STAGES=frozenset(('plan','output','token','directory','api_run','api_job',
 'api_artifact','archive_redirect','archive_download','archive_verify','api_verify'))
DIAGNOSTIC_REASONS=frozenset(('api_pin','archive_redirect','download_deadline','download_size',
 'missing_redirect','archive_response','archive_digest','archive_size','archive_file',
 'zip_entries','zip_bundle_digest','api_file_changed','producer_job','producer_upload',
 'output_location','token','plan_schema','plan_version','producer_pin','harness_pin',
 'artifact_pins','artifact_id','artifact_digest','api_pins','api_digest','reviewed_change_set',
 'closure','closure_path','closure_digest'))
DIAGNOSTIC_STAGE='plan'
DIAGNOSTIC_HTTP_STATUS=0

def failure_diagnostic(error):
 stage=DIAGNOSTIC_STAGE if DIAGNOSTIC_STAGE in DIAGNOSTIC_STAGES else 'plan'
 status=error.code if isinstance(error,urllib.error.HTTPError) else DIAGNOSTIC_HTTP_STATUS
 status=status if type(status) is int and 100<=status<=599 else 0
 if isinstance(error,urllib.error.HTTPError):category='http'
 elif isinstance(error,TimeoutError):category='timeout'
 elif isinstance(error,L.V.A.Rejected):
  code=error.args[0] if len(error.args)==1 else None
  category=code if type(code) is str and code in DIAGNOSTIC_REASONS else 'rejected'
 else:category='internal'
 pin=stage[4:] if category=='api_pin' and stage in ('api_run','api_job','api_artifact') else 'none'
 print('CI_FINANCIAL_REUSE_ACQUISITION_DIAGNOSTIC '+json.dumps(dict(version=1,
  stage=stage,category=category,api_pin=pin,http_status=status),sort_keys=True,separators=(',',':')),flush=True)

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None


def api_headers(token):
 return {'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json',
         'X-GitHub-Api-Version':'2022-11-28','User-Agent':'pactloom-qualified-artifact-acquisition'}


def redirect_target(url):
 parsed=urllib.parse.urlsplit(url)
 L.V.require(parsed.scheme=='https' and parsed.port in (None,443) and parsed.username is None
  and parsed.password is None and not parsed.fragment and parsed.hostname is not None
  and (parsed.hostname.endswith('.blob.core.windows.net') or
       parsed.hostname.endswith('.actions.githubusercontent.com')),'archive_redirect')
 return url


def bounded_read(response,limit,deadline,destination=None):
 count=0;chunks=[]
 while True:
  L.V.require(time.monotonic()<deadline,'download_deadline')
  chunk=response.read(min(1024*1024,limit-count+1))
  if not chunk:break
  count+=len(chunk);L.V.require(count<=limit,'download_size')
  if destination is None:chunks.append(chunk)
  else:destination.write(chunk)
 return b''.join(chunks) if destination is None else count


def acquire(plan,output,token):
 global DIAGNOSTIC_STAGE,DIAGNOSTIC_HTTP_STATUS
 L.validate_plan(plan)
 api=urllib.request.build_opener(NoRedirect());deadline=time.monotonic()+300
 base='https://api.github.com/repos/stanleykosi/pactloom/actions/'
 paths={'run':'runs/'+str(L.V.PRODUCER['run_id']),
        'job':'jobs/'+str(L.V.JOB_ID),'artifact':'artifacts/'+str(plan['artifact_pins']['artifact_id'])}
 for name,path in paths.items():
  DIAGNOSTIC_STAGE='api_'+name
  request=urllib.request.Request(base+path,headers=api_headers(token))
  with api.open(request,timeout=30) as response:raw=bounded_read(response,8*1024*1024,deadline)
  value=json.loads(raw,object_pairs_hook=L.V.A.pairs);canonical=L.V.A.canonical(value)
  L.V.require(hashlib.sha256(canonical).hexdigest()==plan['api_pins'][name],'api_pin')
  (output/(name+'.json')).write_bytes(canonical)
 DIAGNOSTIC_STAGE='archive_redirect'
 request=urllib.request.Request(base+paths['artifact']+'/zip',headers=api_headers(token))
 try:
  # API archive endpoint MUST redirect; do not accidentally save a JSON response.
  with api.open(request,timeout=30):raise L.V.A.Rejected('missing_redirect')
 except urllib.error.HTTPError as response:
  DIAGNOSTIC_HTTP_STATUS=response.code if type(response.code) is int and 100<=response.code<=599 else 0
  L.V.require(response.code in (301,302,303,307,308),'archive_response')
  url=redirect_target(response.headers['Location']);response.close()
 DIAGNOSTIC_HTTP_STATUS=0
 DIAGNOSTIC_STAGE='archive_download'
 # Deliberately new request without token, Authorization, cookies or Referer.
 request=urllib.request.Request(url,headers={'User-Agent':'pactloom-qualified-artifact-acquisition'})
 with api.open(request,timeout=30) as response,(output/'producer.zip').open('xb') as destination:
  bounded_read(response,MAX_ARCHIVE,deadline,destination)
 DIAGNOSTIC_STAGE='archive_verify'
 L.V.archive_digest(output/'producer.zip',plan['artifact_pins'])
 # Re-validate pinned API artifacts; no downloaded manifest supplies trust.
 DIAGNOSTIC_STAGE='api_verify'
 L.verified_api(output,plan)


def acquire_command(raw,output_path):
 global DIAGNOSTIC_STAGE,DIAGNOSTIC_HTTP_STATUS
 os.umask(0o077)
 DIAGNOSTIC_STAGE='plan';DIAGNOSTIC_HTTP_STATUS=0
 created=False;token=''
 try:
  plan=L.validate_plan(json.loads(raw,object_pairs_hook=L.V.A.pairs))
  DIAGNOSTIC_STAGE='output';output=pathlib.Path(output_path).resolve()
  temp=pathlib.Path(os.environ['RUNNER_TEMP']).resolve()
  L.V.require(output.parent==temp and output.name.startswith('wholepact-financial-reuse-download-'),'output_location')
  DIAGNOSTIC_STAGE='token';token=os.environ.pop('FINANCIAL_ARTIFACT_READ_TOKEN','')
  L.V.require(type(token) is str and 0<len(token)<=8192 and '\n' not in token and '\r' not in token,'token')
  DIAGNOSTIC_STAGE='directory';output.mkdir(mode=0o700,exist_ok=False);created=True
  acquire(plan,output,token)
 except BaseException as error:
  try:failure_diagnostic(error)
  except BaseException:pass # Diagnostics must never bypass original owned cleanup.
  if created:shutil.rmtree(output)
  raise
 finally:token=''
 print('CI_FINANCIAL_REUSE_ACQUIRED {"verified":true,"pre_runtime":true}',flush=True)
 return 0

if __name__=='__main__':
 print('CI_FINANCIAL_REUSE_ACQUIRED {"verified":false,"code":"tracked_launcher_required"}',flush=True)
 sys.exit(1)
