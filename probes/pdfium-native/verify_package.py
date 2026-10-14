"""No-extraction static diagnostic package verification; originals never inputs."""
import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from host_probe import FIXTURE_SHA
from package_inputs import source_hashes


def allowed_entries(engine):
    notices={'notices/licenses/'+p.name for p in (engine/'android-arm/licenses').iterdir() if p.is_file()}
    return notices | {'AndroidManifest.xml','resources.arsc','assets/fixture.pdf','classes.dex','notices/PDFium-LICENSE',
                      'META-INF/ANDROIDD.SF','META-INF/ANDROIDD.RSA','META-INF/MANIFEST.MF'} | {
                      f'lib/{abi}/{name}' for abi in ('armeabi-v7a','arm64-v8a') for name in ('libpdfium.so','librtlpdfiumprobe.so')}


def verify_payload(package,allowed,receipt,expected_commit,source):
    entries=package.namelist()
    if len(entries)!=len(set(entries)) or set(entries)!=allowed:
        raise ValueError('Complete diagnostic entry allowlist mismatch')
    if receipt.get('schema')!=1 or receipt.get('sourceCommit')!=expected_commit or receipt.get('sourceHashes')!=source_hashes(source):
        raise ValueError('Exact reviewed source receipt mismatch')
    if receipt.get('payloadHashes')!={n:hashlib.sha256(package.read(n)).hexdigest() for n in entries}:
        raise ValueError('Executable/package receipt drift')


def verify(apk,engine,aapt,receipt_path,expected_commit):
    lock=json.loads(Path(__file__).with_name('pdfium.lock.json').read_text(encoding='utf-8'))
    receipt=json.loads(receipt_path.read_text(encoding='utf-8'))
    if hashlib.sha256(apk.read_bytes()).hexdigest()!=receipt.get('apkSha256'):
        raise ValueError('Whole signed APK receipt drift')
    with zipfile.ZipFile(apk) as package:
        verify_payload(package,allowed_entries(engine),receipt,expected_commit,Path(__file__).parent)
        entries=package.namelist()
        if len(entries)!=len(set(entries)) or len(entries)>100:
            raise ValueError('Duplicate/large package')
        if any(n.startswith('/') or '\\' in n or '..' in n.split('/') for n in entries):
            raise ValueError('Unsafe package path')
        if hashlib.sha256(package.read('assets/fixture.pdf')).hexdigest()!=FIXTURE_SHA:
            raise ValueError('Embedded fixture drift')
        for abi,vendor in [('armeabi-v7a','android-arm'),('arm64-v8a','android-arm64')]:
            name=f'lib/{abi}/libpdfium.so'
            if hashlib.sha256(package.read(name)).hexdigest()!=lock['extractedBinaries'][f'{vendor}/lib/libpdfium.so']:
                raise ValueError('Packaged engine drift')
            if len(package.read(f'lib/{abi}/librtlpdfiumprobe.so'))<1000:
                raise ValueError('Missing native reader boundary')
        if package.read('notices/PDFium-LICENSE')!=(engine/'android-arm/LICENSE').read_bytes():
            raise ValueError('Engine notice drift')
        for notice in (engine/'android-arm/licenses').iterdir():
            if notice.is_file() and package.read('notices/licenses/'+notice.name)!=notice.read_bytes():
                raise ValueError('Missing linked native notice')
        dex=package.read('classes.dex')
        for marker in [b'Lcom/techrebbe/rtl/pdfiumprobe/ProbeActivity;',b'Lcom/techrebbe/rtl/pdfiumprobe/NativeCore;',b'Lcom/techrebbe/rtl/pdfiumprobe/EngineQueue;',b'Lcom/techrebbe/rtl/pdfiumprobe/Interaction;',FIXTURE_SHA.encode()]:
            if marker not in dex:
                raise ValueError('Required executable/fixture marker absent')
        for forbidden in [b'Landroid/webkit/WebView;',b'Lcom/supernote/',b'android.permission.WRITE',b'Runtime.exec']:
            if forbidden in dex:
                raise ValueError('Unexpected browser/device/writer boundary')
    badging=subprocess.run([str(aapt),'dump','badging',str(apk)],check=True,capture_output=True,text=True).stdout
    if "package: name='com.techrebbe.rtl.pdfiumprobe' versionCode='1' versionName='0.1.0-pdfium-exp1'" not in badging:
        raise ValueError('Diagnostic package identity mismatch')
    if 'uses-permission:' in badging or 'uses-permission-sdk-' in badging:
        raise ValueError('Diagnostic must have zero Android permissions')
    if "minSdkVersion:'23'" not in badging or "targetSdkVersion:'35'" not in badging:
        raise ValueError('SDK bounds mismatch')
    print(json.dumps({'package':lock['diagnosticPackage'],'permissions':0,'nativeAbis':['armeabi-v7a','arm64-v8a'],'fixtureSha256':FIXTURE_SHA,'apkSha256':hashlib.sha256(apk.read_bytes()).hexdigest(),'androidRuntime':'UNVERIFIED'}))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--apk',type=Path,required=True)
    parser.add_argument('--engine',type=Path,required=True)
    parser.add_argument('--aapt',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--expected-commit',required=True)
    options=parser.parse_args()
    verify(options.apk,options.engine,options.aapt,options.receipt,options.expected_commit)
