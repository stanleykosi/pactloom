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
 L.validate_plan(plan)
 api=urllib.request.build_opener(NoRedirect());deadline=time.monotonic()+300
 base='https://api.github.com/repos/stanleykosi/pactloom/actions/'
 paths={'run':'runs/'+str(L.V.PRODUCER['run_id']),
        'job':'jobs/'+str(L.V.JOB_ID),'artifact':'artifacts/'+str(plan['artifact_pins']['artifact_id'])}
 for name,path in paths.items():
  request=urllib.request.Request(base+path,headers=api_headers(token))
  with api.open(request,timeout=30) as response:raw=bounded_read(response,8*1024*1024,deadline)
  value=json.loads(raw,object_pairs_hook=L.V.A.pairs);canonical=L.V.A.canonical(value)
  L.V.require(hashlib.sha256(canonical).hexdigest()==plan['api_pins'][name],'api_pin')
  (output/(name+'.json')).write_bytes(canonical)
 request=urllib.request.Request(base+paths['artifact']+'/zip',headers=api_headers(token))
 try:
  # API archive endpoint MUST redirect; do not accidentally save a JSON response.
  with api.open(request,timeout=30):raise L.V.A.Rejected('missing_redirect')
 except urllib.error.HTTPError as response:
  L.V.require(response.code in (301,302,303,307,308),'archive_response')
  url=redirect_target(response.headers['Location']);response.close()
 # Deliberately new request without token, Authorization, cookies or Referer.
 request=urllib.request.Request(url,headers={'User-Agent':'pactloom-qualified-artifact-acquisition'})
 with api.open(request,timeout=30) as response,(output/'producer.zip').open('xb') as destination:
  bounded_read(response,MAX_ARCHIVE,deadline,destination)
 L.V.archive_digest(output/'producer.zip',plan['artifact_pins'])
 # Re-validate pinned API artifacts; no downloaded manifest supplies trust.
 L.verified_api(output,plan)


def acquire_command(raw,output_path):
 os.umask(0o077)
 plan=L.validate_plan(json.loads(raw,object_pairs_hook=L.V.A.pairs));output=pathlib.Path(output_path).resolve()
 temp=pathlib.Path(os.environ['RUNNER_TEMP']).resolve()
 L.V.require(output.parent==temp and output.name.startswith('wholepact-financial-reuse-download-'),'output_location')
 token=os.environ.pop('FINANCIAL_ARTIFACT_READ_TOKEN','')
 L.V.require(type(token) is str and 0<len(token)<=8192 and '\n' not in token and '\r' not in token,'token')
 output.mkdir(mode=0o700,exist_ok=False)
 try:acquire(plan,output,token)
 except BaseException:
  shutil.rmtree(output);raise
 finally:token=''
 print('CI_FINANCIAL_REUSE_ACQUIRED {"verified":true,"pre_runtime":true}',flush=True)
 return 0

if __name__=='__main__':
 print('CI_FINANCIAL_REUSE_ACQUIRED {"verified":false,"code":"tracked_launcher_required"}',flush=True)
 sys.exit(1)
