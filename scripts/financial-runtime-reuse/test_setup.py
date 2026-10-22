"""Create a real reviewed L Git fixture; no native runtime or network."""
import importlib.util
import os
import pathlib
import shutil
import subprocess
import tempfile
from unittest.mock import patch
HERE=pathlib.Path(__file__).resolve().parent
TEMP=tempfile.TemporaryDirectory(prefix='reviewed-launcher-test-')
ROOT=pathlib.Path(TEMP.name)/'L';ROOT.mkdir()
for name in ('launch_adapter.py','verify_option.py','producer_artifacts.py','acquire_archive.py'):
 shutil.copy2(HERE/name,ROOT/name)
shutil.copytree(HERE/'cleanup_snapshot',ROOT/'cleanup_snapshot')
(ROOT/'.gitignore').write_text('private/\n__pycache__/\n')
def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],stderr=subprocess.DEVNULL)
git('init');git('add','.');git('-c','user.name=Tests','-c','user.email=test@example.invalid','commit','-m','reviewed fixture')
SHA=git('rev-parse','HEAD').strip().decode()
ENV=dict(PATH=os.environ['PATH'],RUNNER_TEMP=TEMP.name,GITHUB_ACTIONS='true',RUNNER_OS='Linux',
 RUNNER_ENVIRONMENT='github-hosted',GITHUB_REPOSITORY='stanleykosi/pactloom',
 GITHUB_REF='refs/heads/qualification/durable-proposal-v1',GITHUB_EVENT_NAME='push',
 GITHUB_JOB='synthetic-only',GITHUB_SHA=SHA,GITHUB_RUN_ID='100',GITHUB_RUN_ATTEMPT='1')
spec=importlib.util.spec_from_file_location('test_reviewed_launcher',ROOT/'launch_adapter.py')
L=importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name]=L;spec.loader.exec_module(L)
with patch.dict(os.environ,ENV,clear=True):
 TRUSTED,_=L.bootstrap(ROOT);V=L.load_helpers(TRUSTED)
A=TRUSTED.module('test_reviewed_acquire',ROOT/'acquire_archive.py',L=L)
