"""Concrete first-review regressions; no Android/device or PDF mutation."""
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from package_inputs import archive_files,source_hashes
from verify_package import verify_payload

SOURCE=Path(__file__).parent


class ReviewedBoundaries(unittest.TestCase):
    def test_observed_budget_regression_and_heap_guard_mutants(self):
        java=Path(os.environ['JAVA_HOME'])/'bin'
        source=(SOURCE/'RenderBudget.java').read_text()
        mutants=[source.replace('MAX_PIXELS=6000000','MAX_PIXELS=4000000'),
                 source.replace('if(pixels>MAX_PIXELS || oldBitmapBytes>maxHeap/2\n                ||pixels*8+MODEL_RESERVE>maxHeap/2-oldBitmapBytes)', 'if(pixels>MAX_PIXELS)')]
        for mutant in mutants:
            self.assertNotEqual(mutant,source)
            with tempfile.TemporaryDirectory(prefix='pdfium-budget-mutant-') as out:
                path=Path(out)/'RenderBudget.java'
                path.write_text(mutant,encoding='utf-8') # generated mechanical test variant only
                subprocess.run([str(java/'javac.exe'),'-encoding','UTF-8','-d',out,str(path),str(SOURCE/'RenderBudgetTest.java')],check=True)
                result=subprocess.run([str(java/'java.exe'),'-cp',out,'com.techrebbe.rtl.pdfiumprobe.RenderBudgetTest'],capture_output=True,text=True,timeout=15)
                self.assertNotEqual(result.returncode,0,'Defect mutant survived')

    def test_observed_nomad_xyz_budget_and_utf8_build(self):
        java=Path(os.environ['JAVA_HOME'])/'bin'
        with tempfile.TemporaryDirectory(prefix='pdfium-budget-') as output:
            subprocess.run([str(java/'javac.exe'),'-encoding','UTF-8','-d',output,*[str(SOURCE/n) for n in ('RenderBudget.java','RenderBudgetTest.java')]],check=True)
            result=subprocess.run([str(java/'java.exe'),'-cp',output,'com.techrebbe.rtl.pdfiumprobe.RenderBudgetTest'],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('14 assertions PASS',result.stdout)
        activity=(SOURCE/'ProbeActivity.java').read_text()
        self.assertIn('RenderBudget.dimensions(size[0],size[1],scale,maxHeap,oldBitmapBytes)',activity)
        self.assertIn('error instanceof RenderBudget.Exceeded',activity)
        self.assertIn('constexpr int kPixels=6000000',(SOURCE/'native_core.cpp').read_text())
        self.assertIn('static final int MAX_PIXELS=6000000',(SOURCE/'RenderBudget.java').read_text())
        self.assertIn('javac.exe\') -encoding UTF-8',(SOURCE/'build_probe.ps1').read_text())

    def test_actual_java_interaction_and_process_fifo(self):
        java=Path(os.environ['JAVA_HOME'])/'bin'
        with tempfile.TemporaryDirectory(prefix='pdfium-jdk-') as output:
            subprocess.run([str(java/'javac.exe'),'-d',output,*[str(SOURCE/n) for n in ('Interaction.java','EngineQueue.java','InteractionTest.java')]],check=True)
            result=subprocess.run([str(java/'java.exe'),'-cp',output,'com.techrebbe.rtl.pdfiumprobe.InteractionTest'],check=True,capture_output=True,text=True,timeout=15)
            self.assertIn('16 assertions PASS',result.stdout)

    def test_android_uses_corrected_helpers_at_both_contact_edges(self):
        activity=(SOURCE/'ProbeActivity.java').read_text()
        self.assertEqual(activity.count('dragged=Interaction.dragged('),2)
        self.assertEqual(activity.count('EngineQueue.execute('),3)
        self.assertNotIn('engine.shutdown',activity)
        self.assertIn('Interaction.copy(model.getString("text")',activity)
        self.assertIn('canvas.clipRect(x,y,x+bitmap.getWidth(),y+bitmap.getHeight())',activity)
        self.assertEqual(activity.count('Interaction.inside(px,py,bitmap.getWidth(),bitmap.getHeight())'),2)
        native=(SOURCE/'native_core.cpp').read_text()
        self.assertEqual(native.count('cropRect(crop,l,b,r,t)'),2)
        self.assertIn('minX=std::clamp(minX,0,w)',native)
        self.assertIn('FPDFText_IsGenerated(text.value,i)==1',native)
        self.assertIn('else gap.clear()',native)

    def test_compiler_never_uses_stale_extracted_headers(self):
        build=(SOURCE/'build_probe.ps1').read_text()
        self.assertLess(build.index('$engine=$authenticated'),build.index('clang++.exe'))
        self.assertIn('package_inputs.py\') prepare --engine $engine --output $authenticated',build)

    def test_archive_drift_and_links_and_traversal_rejected(self):
        with tempfile.TemporaryDirectory(prefix='pdfium-tar-') as out:
            archive=Path(out)/'engine.tgz'
            for name,kind in [('include/fpdfview.h',tarfile.REGTYPE),('../bad',tarfile.REGTYPE),('include/link.h',tarfile.SYMTYPE)]:
                with tarfile.open(archive,'w:gz') as package:
                    item=tarfile.TarInfo(name);item.type=kind;item.size=1 if kind==tarfile.REGTYPE else 0
                    package.addfile(item,io.BytesIO(b'x') if item.size else None)
                pin=hashlib.sha256(archive.read_bytes()).hexdigest()
                if kind==tarfile.REGTYPE and name.startswith('include/'):
                    self.assertEqual(archive_files(archive,pin),{name:b'x'})
                    with self.assertRaises(ValueError):archive_files(archive,'0'*64)
                else:
                    with self.assertRaises(ValueError):archive_files(archive,pin)

    def test_extra_payload_wrapper_drift_and_source_drift_rejected(self):
        original={'classes.dex':b'dex','lib/arm64-v8a/librtlpdfiumprobe.so':b'wrapper'}
        receipt={'schema':1,'sourceCommit':'a'*40,'sourceHashes':source_hashes(SOURCE),
                 'payloadHashes':{n:hashlib.sha256(data).hexdigest() for n,data in original.items()}}
        def check(payload,record=receipt):
            output=io.BytesIO()
            with zipfile.ZipFile(output,'w') as package:
                for name,data in payload.items():package.writestr(name,data)
            output.seek(0)
            with zipfile.ZipFile(output) as package:
                verify_payload(package,set(original),record,'a'*40,SOURCE)
        check(original)
        for extra in ('classes2.dex','lib/arm64-v8a/other.so','assets/personal.pdf'):
            with self.assertRaises(ValueError):check({**original,extra:b'unreviewed'})
        with self.assertRaises(ValueError):check({**original,'lib/arm64-v8a/librtlpdfiumprobe.so':b'changed'})
        with self.assertRaises(ValueError):check(original,{**receipt,'sourceCommit':'b'*40})
        with self.assertRaises(ValueError):check(original,{**receipt,'sourceHashes':{}})


if __name__=='__main__':
    unittest.main(verbosity=2)
