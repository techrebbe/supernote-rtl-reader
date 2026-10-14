"""Fresh build inputs from pinned archives; complete source/payload receipt."""
import argparse
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

SOURCES=('AndroidManifest.xml','NativeCore.java','ProbeActivity.java','Interaction.java',
         'EngineQueue.java','native_core.cpp','build_probe.ps1','pdfium.lock.json',
         'package_inputs.py','verify_package.py','host_probe.py','fetch_engine.ps1')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive_files(archive,expected_hash):
    data=archive.read_bytes()
    if sha(data)!=expected_hash:
        raise ValueError('Archive hash drift')
    with tarfile.open(archive,'r:gz') as package:
        members=package.getmembers()
        if not members or len(members)>1000:
            raise ValueError('Archive member bound')
        result={}
        for member in members:
            name=member.name.removeprefix('./').rstrip('/')
            if name in ('','.') and member.isdir():
                continue
            if ('\\' in name or ':' in name or PurePosixPath(name).is_absolute()
                    or '..' in name.split('/') or not (member.isfile() or member.isdir())):
                raise ValueError('Unsafe archive member')
            if member.isfile():
                if name in result or member.size>20000000:
                    raise ValueError('Duplicate/large archive file')
                result[name]=package.extractfile(member).read()
        if sum(map(len,result.values()))>100000000:
            raise ValueError('Archive byte bound')
        return result


def prepare(engine,target,source):
    lock=json.loads((source/'pdfium.lock.json').read_text())
    if target.exists():
        raise ValueError('Fresh authenticated input directory required')
    target.mkdir()
    for vendor in ('android-arm','android-arm64'):
        name='pdfium-'+vendor+'.tgz'
        inventory=archive_files(engine/name,lock['assets'][name]['sha256'])
        if sha(inventory['lib/libpdfium.so'])!=lock['extractedBinaries'][vendor+'/lib/libpdfium.so']:
            raise ValueError('Authenticated engine binary drift')
        flags=inventory['args.gn'].decode()
        if not all(line in flags.splitlines() for line in ('pdf_enable_v8 = false','pdf_enable_xfa = false','default_min_sdk_version = 23')):
            raise ValueError('Authenticated build flags rejected')
        # The compiler never reads independently mutable pre-extracted headers.
        root=target/vendor
        root.mkdir()
        for name,data in inventory.items():
            path=root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            with path.open('xb') as output:
                output.write(data)


def source_hashes(source):
    result={name:sha((source/name).read_bytes()) for name in SOURCES}
    result['../../scripts/normalize_apk_zip.py']=sha((source/'../../scripts/normalize_apk_zip.py').read_bytes())
    return result


def receipt(apk,source,commit,output):
    if len(commit)!=40 or any(c not in '0123456789abcdef' for c in commit):
        raise ValueError('Exact source commit required')
    with zipfile.ZipFile(apk) as package:
        names=package.namelist()
        if len(names)!=len(set(names)):
            raise ValueError('Duplicate payload')
        payload={name:sha(package.read(name)) for name in names}
    data={'schema':1,'sourceCommit':commit,'sourceHashes':source_hashes(source),
          'apkSha256':sha(apk.read_bytes()),'payloadHashes':payload}
    with output.open('x',encoding='utf-8') as handle:
        json.dump(data,handle,indent=2,sort_keys=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=['prepare','receipt'])
    parser.add_argument('--engine',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--apk',type=Path)
    parser.add_argument('--commit')
    args=parser.parse_args()
    source=Path(__file__).parent
    if args.mode=='prepare':
        prepare(args.engine,args.output,source)
    else:
        receipt(args.apk,source,args.commit,args.output)
