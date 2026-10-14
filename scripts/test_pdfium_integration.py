"""Concrete generated-App integration, actual ledger and source regression gates."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from patch_pdfium_reader import patch_app, patch_index

ROOT=Path(__file__).resolve().parent.parent


def generated(output):
    app=output/'App.js';index=output/'index.js'
    app.write_text((ROOT/'overlay/App.js').read_text(encoding='utf-8').replace(
        '<View style={styles.footer}>',"<View style={[styles.footer, {direction: 'ltr'}]}>"),encoding='utf-8')
    index.write_text((ROOT/'overlay/index.js').read_text(encoding='utf-8'),encoding='utf-8')
    subprocess.run([sys.executable,str(ROOT/'scripts/patch_direct_view.py'),str(app)],check=True)
    # Same direction-only prefetch transform used by install_native.py.
    spec=importlib.util.spec_from_file_location('canonical_installer',ROOT/'scripts/install_native.py')
    installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
    installer.patch_app_prefetch_direction(app)
    subprocess.run([sys.executable,str(ROOT/'scripts/patch_initial_layout.py'),str(app)],check=True)
    a=patch_app(app.read_text(encoding='utf-8'));b=patch_index(index.read_text(encoding='utf-8'))
    app.write_text(a,encoding='utf-8');index.write_text(b,encoding='utf-8')
    return a,b


class Integration(unittest.TestCase):
    def test_real_generated_slots_and_guards(self):
        with tempfile.TemporaryDirectory(prefix='pdfium-integrated-app-') as temp:
            app,index=generated(Path(temp))
            self.assertEqual(app.count('<InteractivePdfPage'),3)
            self.assertNotIn('<NativePdfPageView',app)
            host=app[app.index('      <ReaderKeyView'):app.index("        {display.kind === 'spread'",app.index('      <ReaderKeyView'))]
            self.assertNotIn('panResponderRef.current.panHandlers',host)
            self.assertEqual(app.count('<View style={styles.blankPage} {...panResponderRef.current.panHandlers} />'),2)
            for slot in ('single','left','right'):self.assertIn(f'slot="{slot}"',app)
            self.assertIn('pageAreaLayout.height,',app)
            self.assertIn('readerWindowLayout.width > readerWindowLayout.height',app)
            self.assertNotIn('? pageAreaLayout.width > pageAreaLayout.height',app)
            self.assertIn('const savedInkProfile = null;',app)
            self.assertIn('restoreSourcePreferences(rawPreferences, openedPdf.sourceSha256)',app)
            self.assertIn('pdfSourceSha256: pdfium.owner?.sourceSha256',app)
            self.assertIn('const nextLogicalPage = () => goBy(pageStep());',app)
            self.assertIn('const previousLogicalPage = () => goBy(-pageStep());',app)
            self.assertIn('turn={action => action',app)
            subprocess.run(['node',str(ROOT/'scripts/test_pdfium_generated_callbacks.js'),str(Path(temp)/'App.js')],check=True)
            self.assertIn('await pdfium.close(true);',app)
            self.assertLess(app.index("await savePreferences('edit', payload);"),app.index('await pdfium.close(true);'))
            self.assertLess(app.index('await pdfium.close(true);'),app.index('        await handoffSavedPage({'))
            self.assertIn('await pdfiumOwner.close(!pdfiumOwner.sourceInvalid.current)',index)
            # No changed private-config/native-restart implementation is introduced.
            self.assertEqual(app.count('        await handoffSavedPage({'),1)

    def test_patch_drift_fails_not_partial(self):
        with tempfile.TemporaryDirectory(prefix='pdfium-integrated-drift-') as temp:
            app,index=generated(Path(temp))
            with self.assertRaises(ValueError):patch_app(app)
            with self.assertRaises(ValueError):patch_index(index)

    def test_aggregate_ledger_actual_java(self):
        home=Path(os.environ['JAVA_HOME'])/'bin'
        suffix='.exe' if os.name=='nt' else ''
        with tempfile.TemporaryDirectory(prefix='pdfium-ledger-') as temp:
            root=Path(temp)
            (root/'PdfiumRasterLedger.java').write_text((ROOT/'native/PdfiumRasterLedger.java.template').read_text().replace('__PACKAGE__','test'),encoding='utf-8')
            (root/'PdfiumViewport.java').write_text((ROOT/'native/PdfiumViewport.java.template').read_text().replace('__PACKAGE__','test'),encoding='utf-8')
            (root/'LedgerTest.java').write_text('''package test;
public class LedgerTest {
static void ok(boolean b){if(!b)throw new AssertionError();}
public static void main(String[] args){
PdfiumRasterLedger ledger=new PdfiumRasterLedger(100000000);
PdfiumRasterLedger.Lease a=ledger.reserve(3000000,0);a.installed();
ok(ledger.used()==12000000);PdfiumRasterLedger.Lease b=ledger.reserve(3000000,0);ok(ledger.used()==38097152);
boolean refused=false;try{ledger.reserve(3000000,0);}catch(IllegalStateException e){refused=true;}ok(refused);
b.release();b.release();ok(ledger.used()==12000000);
a.installed();ok(ledger.used()==12000000);a.release();ok(ledger.used()==0);
refused=false;try{ledger.reserve(6000001,0);}catch(IllegalArgumentException e){refused=true;}ok(refused);
refused=false;try{ledger.reserve(5000000,20000000);}catch(IllegalStateException e){refused=true;}ok(refused);
ok(PdfiumViewport.baseScale(600,800,600,800,"native_fill",null)==1);
ok(PdfiumViewport.baseScale(600,800,600,800,"native_fill","Fit")==.96);
ok(PdfiumViewport.baseScale(600,800,600,800,"fit","Fit")==.96);
ok(PdfiumViewport.baseScale(900,600,600,800,"native_fill","Fit")==.72);
ok(PdfiumViewport.baseScale(900,600,600,800,"native_fill",null)==1.5);
refused=false;try{PdfiumViewport.baseScale(20,600,600,800,"fit","Fit");}catch(IllegalArgumentException e){refused=true;}ok(refused);
System.out.println("14 actual shared-raster/Fit assertions PASS");}}
''',encoding='utf-8')
            subprocess.run([str(home/('javac'+suffix)),'-encoding','UTF-8','-d',temp,
                str(root/'PdfiumRasterLedger.java'),str(root/'PdfiumViewport.java'),str(root/'LedgerTest.java')],check=True)
            subprocess.run([str(home/('java'+suffix)),'-cp',temp,'test.LedgerTest'],check=True)


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--emit':
        output=Path(sys.argv[2]);output.mkdir(parents=True,exist_ok=False);generated(output)
        java=output/'android/app/src/main/java/com/supernotertlreader';java.mkdir(parents=True)
        (java/'PdfRendererPackage.kt').write_text((ROOT/'native/PdfRendererPackage.kt.template').read_text().replace(
            '__PACKAGE__','com.supernotertlreader'),encoding='utf-8')
    else:unittest.main()
