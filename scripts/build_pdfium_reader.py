"""Authenticate, compile and register the read-only PDFium production adapter."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

JAVA = ('PdfiumReaderCore','PdfiumRasterLedger','PdfiumSession','PdfiumReaderModule',
        'PdfiumPageView','PdfiumPageViewManager')


def source_inputs(root):
    source=root/'probes/pdfium-native'
    return [root/'native'/f'{name}.java.template' for name in JAVA]+[
        root/'native/pdfium_reader_core.cpp',source/'native_core.cpp',source/'Interaction.java',
        source/'RenderBudget.java',source/'pdfium.lock.json',source/'package_inputs.py',
        root/'scripts/build_pdfium_reader.py',root/'scripts/patch_pdfium_reader.py',
        root/'scripts/verify_pdfium_reader.py',root/'provenance/pdfium-reader.json',
        root/'overlay/interactivePdf.js',root/'overlay/InteractivePdfReader.js']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(project, root, engine, sdk):
    if not (project/'android/app/src/main').is_dir():
        raise ValueError('Generated Android project missing')
    source=root/'probes/pdfium-native'
    lock=json.loads((source/'pdfium.lock.json').read_text())
    for name in ('pdfium-android-arm.tgz','pdfium-android-arm64.tgz','pdfium-attestation.json'):
        if digest(engine/name)!=lock['assets'][name]['sha256']:
            raise ValueError('Pinned engine/provenance hash mismatch')
    spec=importlib.util.spec_from_file_location('pdfium_authenticated_inputs',source/'package_inputs.py')
    inputs=importlib.util.module_from_spec(spec);spec.loader.exec_module(inputs)
    work=project/'build/pdfium-reader'
    if work.exists():raise ValueError('Fresh PDFium compiler output required')
    work.mkdir(parents=True)
    authenticated=work/'authenticated-engine';inputs.prepare(engine,authenticated,source)
    host='windows-x86_64' if os.name=='nt' else 'linux-x86_64'
    tools=sdk/'ndk/27.0.12077973/toolchains/llvm/prebuilt'/host/'bin'
    compiler=tools/('clang++.exe' if os.name=='nt' else 'clang++')
    readelf=tools/('llvm-readelf.exe' if os.name=='nt' else 'llvm-readelf')
    output=project/'android/app/src/main'
    native=output/'jniLibs'
    if any(native.glob('*/libpdfium.so')) or any(native.glob('*/librtlpdfiumreader.so')):
        raise ValueError('Pre-existing PDFium payload rejected')
    payload={}
    exports={f'Java_com_supernotertlreader_PdfiumReaderCore_{name}' for name in
             ('open','close','count','outline','size','point','model','render','libraryPath')}
    for abi,target,vendor in (('armeabi-v7a','armv7a-linux-androideabi23','android-arm'),
                             ('arm64-v8a','aarch64-linux-android23','android-arm64')):
        destination=native/abi;destination.mkdir(parents=True,exist_ok=True)
        wrapper=destination/'librtlpdfiumreader.so';dep=authenticated/vendor
        command=[str(compiler),'--target='+target,'-std=c++17','-O2','-fPIC','-shared',
            '-static-libstdc++','-fvisibility=hidden','-Wall','-Wextra','-Werror',
            '-I'+str(dep/'include'),str(root/'native/pdfium_reader_core.cpp'),
            '-L'+str(dep/'lib'),'-lpdfium','-ldl','-Wl,--no-undefined','-Wl,-soname,librtlpdfiumreader.so',
            '-o',str(wrapper)]
        subprocess.run(command,check=True)
        symbols=subprocess.run([str(readelf),'--dyn-syms','--wide',str(wrapper)],check=True,capture_output=True,text=True).stdout
        actual={line.split()[-1] for line in symbols.splitlines() if ' Java_' in line}
        if actual!=exports:raise ValueError('JNI export drift')
        shutil.copyfile(dep/'lib/libpdfium.so',destination/'libpdfium.so')
        payload[f'lib/{abi}/librtlpdfiumreader.so']=digest(wrapper)
        payload[f'lib/{abi}/libpdfium.so']=digest(destination/'libpdfium.so')
    notice=output/'assets/pdfium'
    if notice.exists():raise ValueError('Pre-existing PDFium notices rejected')
    notice.mkdir(parents=True)
    notices=[]
    for vendor in ('android-arm','android-arm64'):
        notices.append({file.relative_to(authenticated/vendor).as_posix():digest(file)
            for file in (authenticated/vendor).rglob('*') if file.is_file() and
            (file.relative_to(authenticated/vendor).as_posix()=='LICENSE' or 'licenses' in file.relative_to(authenticated/vendor).parts)})
    if notices[0]!=notices[1]:raise ValueError('Different ABI notices require an explicit combined inventory')
    shutil.copyfile(authenticated/'android-arm/LICENSE',notice/'LICENSE')
    shutil.copytree(authenticated/'android-arm/licenses',notice/'licenses')
    for file in notice.rglob('*'):
        if file.is_file():payload['assets/'+file.relative_to(output/'assets').as_posix()]=digest(file)
    java=output/'java/com/supernotertlreader'
    if not (java/'PdfRendererPackage.kt').is_file():raise ValueError('Canonical native package missing')
    authored=[root/'native'/f'{name}.java.template' for name in JAVA]
    for file in authored:
        (java/file.name.removesuffix('.template')).write_text(
            file.read_text(encoding='utf-8').replace('__PACKAGE__','com.supernotertlreader'),encoding='utf-8')
    for name in ('Interaction','RenderBudget'):
        (java/f'{name}.java').write_text((source/f'{name}.java').read_text(encoding='utf-8').replace(
            'package com.techrebbe.rtl.pdfiumprobe;','package com.supernotertlreader;'),encoding='utf-8')
    package=java/'PdfRendererPackage.kt';text=package.read_text(encoding='utf-8')
    for before,after in [('        PdfRendererModule(reactContext),','        PdfRendererModule(reactContext),\n        PdfiumReaderModule(reactContext),'),
                         ('        PdfPageViewManager(),','        PdfPageViewManager(),\n        PdfiumPageViewManager(),')]:
        if text.count(before)!=1:raise ValueError('Canonical package registration drift')
        text=text.replace(before,after,1)
    package.write_text(text,encoding='utf-8')
    authored=source_inputs(root)
    receipt={'schema':1,'engineTag':lock['tag'],'sourceHashes':{
        file.relative_to(root).as_posix():digest(file) for file in authored},'payloadHashes':payload}
    (notice/'build-receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2),encoding='utf-8')
    print('PDFium original-reader JNI, Java registrations, notices and payload receipt prepared')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('project',type=Path);parser.add_argument('root',type=Path)
    parser.add_argument('--engine',type=Path,default=os.environ.get('RTL_PDFIUM_ENGINE_ROOT'))
    parser.add_argument('--sdk',type=Path,default=os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT'))
    args=parser.parse_args()
    if args.engine is None or args.sdk is None:raise SystemExit('Set authenticated RTL_PDFIUM_ENGINE_ROOT and ANDROID_HOME; no implicit dependency downgrade')
    build(args.project.resolve(),args.root.resolve(),args.engine.resolve(),args.sdk.resolve())
