"""Pinned financial-only OCR add-on; pure checks, no install or subprocess.

The existing reviewed Debian snapshot/base lock remains unchanged. This module
adds only the authenticated exact Tesseract5.5.0 dependency closure. Neither a
valid lock nor an executable digest proves OCR runtime behavior.
"""
import hashlib
import importlib.util
import json
import lzma
import pathlib
import sys

ROOT=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('financial_ocr_base_image',ROOT/'ci-ui-image.py')
BASE=importlib.util.module_from_spec(spec);sys.modules[spec.name]=BASE;spec.loader.exec_module(BASE)
LOCK_SHA256='23f663250edf3836cda1d5bd49058024630209f09e60f3ab0eaf034256fcbef7'
CANONICAL_SHA256='7f8c70e5cd50b50738b3ed0b02170db306d9009671019ebf6e93a4180b00080e'
EXECUTABLE_SHA256='74b76a5b994adcc18be362bf64ed5118082b2401d5d9a35242e92fc4c62e2b4b'
MAX_LOCK_BYTES=128*1024
MAX_INDEX_BYTES=200*1024*1024

class Rejected(ValueError):
    """Finite errors only, never subprocess/image/OCR contents."""
    def __init__(self,code):
        self.code=code if code in ('pin','shape','closure','metadata','executable','installed') else 'shape'
        super().__init__(self.code)

def require(condition,code='shape'):
    if not condition:raise Rejected(code)

def reviewed(manifest):
    require(hashlib.sha256(BASE._canonical(manifest)).hexdigest()==CANONICAL_SHA256,'pin')

def validate_manifest(raw,base_raw):
    require(type(raw) is bytes and 0<len(raw)<=MAX_LOCK_BYTES,'shape')
    require(hashlib.sha256(raw).hexdigest()==LOCK_SHA256,'pin')
    try:
        manifest=json.loads(raw,object_pairs_hook=BASE._unique)
        base=BASE.validate_manifest(base_raw)
        reviewed(manifest)
        require(manifest['base_lock_sha256']==BASE.LOCK_SHA256 and manifest['base_image']==base['base_image'],'pin')
        require(manifest['archive_origin']==base['archive_origin'] and manifest['suite']=='trixie' and manifest['architecture']=='amd64','pin')
        for key in ('packages_xz_sha256','packages_xz_bytes','release_sha256','signed_release_date'):
            require(manifest['metadata'][key]==base['provenance'][key],'metadata')
        packages={r['name']:r for r in base['packages']}
        bases={r['name']:r for r in base['base_packages']}
        additional=manifest['additional_packages']
        require(len(additional)==20 and len({r['name'] for r in additional})==20,'closure')
        for row in additional:
            name=row['name'];require(name not in packages,'closure');BASE._package_identity(row)
            if row['origin']=='pinned-base':
                require(name in bases and row['version']==bases[name]['version'] and
                        row['architecture']==bases[name]['architecture'] and row['path'] is None and
                        row['sha256'] is None and row['size']==0,'closure')
            else:
                require(row['origin']=='signed-debian-archive' and name not in bases and
                        BASE.SHA.fullmatch(row['sha256']) is not None and row['size']>0,'closure')
            packages[name]=row
        require(manifest['roots']==['tesseract-ocr'] and
                BASE._closure(packages,manifest['roots'])==manifest['ocr_closure'],'closure')
        archive=[r for r in additional if r['origin']=='signed-debian-archive']
        require(manifest['sizes']==dict(archive_packages=len(archive),
            base_packages_reused_additionally=len(additional)-len(archive),
            download_bytes=sum(r['size'] for r in archive),
            declared_new_installed_kib=sum(r['installed_kib'] for r in archive)),'closure')
        require(packages['tesseract-ocr']['version']==packages['libtesseract5']['version']=='5.5.0-1+b1','pin')
        require(manifest['executable']['sha256']==EXECUTABLE_SHA256 and
                manifest['executable']['path']=='/usr/bin/tesseract' and
                manifest['executable']['bytes']==51536,'executable')
        return manifest,base
    except Rejected:raise
    except (KeyError,TypeError,ValueError,BASE.Rejected):
        raise Rejected('shape') from None

def download_plan(manifest):
    reviewed(manifest)
    return tuple(dict(name=r['name'],filename=pathlib.PurePosixPath(r['path']).name,
        url=manifest['archive_origin']+r['path'],size=r['size'],sha256=r['sha256'])
        for r in manifest['additional_packages'] if r['origin']=='signed-debian-archive')

def expected_runtime_packages(manifest,base):
    reviewed(manifest);BASE._reviewed(base)
    expected=BASE.expected_packages(base,'runtime')
    for row in manifest['additional_packages']:
        expected[row['name']]=[row['version'],row['architecture']]
    return expected

def validate_installed(manifest,base,raw):
    require(type(raw) is str and len(raw)<=128*1024,'installed')
    found={}
    for line in raw.splitlines():
        fields=line.split('\t')
        require(len(fields)==4 and fields[3]=='installed' and fields[0] not in found,'installed')
        found[fields[0]]=fields[1:3]
    require(found==expected_runtime_packages(manifest,base),'installed')

def validate_executable(manifest,raw):
    reviewed(manifest)
    require(type(raw) is bytes and len(raw)==manifest['executable']['bytes'] and
            hashlib.sha256(raw).hexdigest()==manifest['executable']['sha256'],'executable')

def audit_authenticated_index(manifest,raw):
    """Optional regeneration audit against the exact already-authenticated index.

    A matching by-hash index is sufficient only because the existing reviewed
    lock already pins its signed-Release-derived digest. No new signature claim.
    """
    reviewed(manifest);meta=manifest['metadata']
    require(type(raw) is bytes and len(raw)==meta['packages_xz_bytes'] and
            hashlib.sha256(raw).hexdigest()==meta['packages_xz_sha256'],'metadata')
    try:
        decoder=lzma.LZMADecompressor();plain=decoder.decompress(raw,max_length=MAX_INDEX_BYTES+1)
        require(decoder.eof and not decoder.unused_data and len(plain)<=MAX_INDEX_BYTES,'metadata')
        wanted={r['name']:r for r in manifest['additional_packages']};found=set()
        for stanza in plain.decode('utf-8').split('\n\n'):
            fields={};last=None
            for line in stanza.splitlines():
                if line.startswith(' ') and last:fields[last]+='\n'+line
                elif ': ' in line:last,value=line.split(': ',1);fields[last]=value
            name=fields.get('Package')
            if name not in wanted:continue
            require(name not in found,'metadata');found.add(name);r=wanted[name]
            for a,b in [('version','Version'),('architecture','Architecture'),('depends','Depends'),
                        ('pre_depends','Pre-Depends'),('provides','Provides')]:
                require(r[a]==fields.get(b,''),'metadata')
            require(r['installed_kib']==int(fields['Installed-Size']),'metadata')
            if r['origin']=='signed-debian-archive':
                require(r['path']==fields['Filename'] and r['size']==int(fields['Size']) and
                        r['sha256']==fields['SHA256'],'metadata')
        require(found==set(wanted),'metadata')
    except Rejected:raise
    except (lzma.LZMAError,UnicodeError,ValueError,KeyError):raise Rejected('metadata') from None
