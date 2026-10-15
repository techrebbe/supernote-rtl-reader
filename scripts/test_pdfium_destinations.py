"""Actual native destination/outline policy, compiled with controlled PDFium peers."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class Destinations(unittest.TestCase):
    def test_bad_destination_is_inert_not_document_fatal(self):
        compiler=os.environ.get('CXX') or shutil.which('g++')
        if not compiler:self.skipTest('C++17 compiler required')
        source=(ROOT/'probes/pdfium-native/native_core.cpp').read_text(encoding='utf-8')
        helpers=source[source.index('std::string number('):source.index('std::string action(')]
        outlines=source[source.index('void bound('):source.index('void dimensions(')]
        cpp=r'''#include <algorithm>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>
using FS_FLOAT=float;using FPDF_BOOL=int;
constexpr int PDFDEST_VIEW_FIT=2,PDFDEST_VIEW_XYZ=1,kItems=1000;
struct Dest {int page,mode=PDFDEST_VIEW_FIT;unsigned long count=0;float zoom=0;bool zoomPresent=false;};
using FPDF_DEST=Dest*;using FPDF_DOCUMENT=void*;FPDF_DOCUMENT document=nullptr;int pageCount=663,viewReads=0;
void require(bool b,const char* message){if(!b)throw std::runtime_error(message);}
int FPDFDest_GetDestPageIndex(FPDF_DOCUMENT,FPDF_DEST d){return d->page;}
unsigned long FPDFDest_GetView(FPDF_DEST d,unsigned long* count,FS_FLOAT*){viewReads++;*count=d->count;return d->mode;}
int FPDFDest_GetLocationInPage(FPDF_DEST d,int* x,int* y,int* z,float* left,float* top,float* zoom){
 *x=*y=0;*left=*top=0;*z=d->zoomPresent;*zoom=d->zoom;return 1;}
/*ACTUAL_DESTINATION_AND_HELPERS*/
struct Node {std::u16string title;Dest* dest;Node* child=nullptr;Node* next=nullptr;};
using FPDF_BOOKMARK=Node*;Node* root=nullptr;
FPDF_BOOKMARK FPDFBookmark_GetFirstChild(FPDF_DOCUMENT,FPDF_BOOKMARK p){return p?p->child:root;}
FPDF_BOOKMARK FPDFBookmark_GetNextSibling(FPDF_DOCUMENT,FPDF_BOOKMARK n){return n->next;}
unsigned long FPDFBookmark_GetTitle(FPDF_BOOKMARK n,void* out,unsigned long size){
 auto bytes=(n->title.size()+1)*2;if(out){require(size==bytes,"fake title size");std::memcpy(out,n->title.c_str(),bytes);}return bytes;}
FPDF_DEST FPDFBookmark_GetDest(FPDF_DOCUMENT,FPDF_BOOKMARK n){return n->dest;}
void* FPDFBookmark_GetAction(FPDF_BOOKMARK){return nullptr;}
std::string action(FPDF_DEST dest,void*){return destination(dest);} // controlled action peer, no dispatch.
/*ACTUAL_OUTLINE*/
int assertions=0;
void ok(bool b){if(!b)throw std::runtime_error("assertion "+std::to_string(assertions));assertions++;}
int main(){
 ok(destination(nullptr).find("unsupported")!=std::string::npos);
 for(int page:{-1,-50,663,10000}){
  Dest bad{page};viewReads=0;auto out=destination(&bad);
  ok(out.find("unsupported")!=std::string::npos);ok(out.find("pageIndex")==std::string::npos);ok(viewReads==0);
 }
 Dest first{0},last{662};
 ok(destination(&first)=="{\"kind\":\"internal\",\"pageIndex\":0,\"mode\":\"Fit\"}");
 ok(destination(&last).find("\"pageIndex\":662")!=std::string::npos);
 Dest xyz{25,PDFDEST_VIEW_XYZ,3,1.25,true};auto pose=destination(&xyz);
 ok(pose.find("\"pageIndex\":25")!=std::string::npos);ok(pose.find("\"zoom\":1.25")!=std::string::npos);
 Dest other{5,999};ok(destination(&other).find("unsupported")!=std::string::npos);
 xyz.zoom=-1;try{destination(&xyz);throw 1;}catch(const std::runtime_error&){assertions++;}
 first.count=5;try{destination(&first);throw 1;}catch(const std::runtime_error&){assertions++;}first.count=0;
 Dest broken{-1};Node child{u"Valid child",&last};Node heading{u"Broken heading",&broken,&child};Node sibling{u"Valid sibling",&first};
 root=&heading;heading.next=&sibling;std::unordered_set<FPDF_BOOKMARK> seen;auto outline=outlines(nullptr,0,seen);
 ok(seen.size()==3);ok(outline.find("unsupported")!=std::string::npos);
 ok(outline.find("\"pageIndex\":662")!=std::string::npos);ok(outline.find("\"pageIndex\":0")!=std::string::npos);
 ok(outline.find("\"pageIndex\":-1")==std::string::npos);ok(outline.find("\"children\":[{")!=std::string::npos);
 child.next=&child;seen.clear();try{outlines(nullptr,0,seen);throw 1;}catch(const std::runtime_error&){assertions++;}
 child.next=nullptr;seen.clear();try{outlines(nullptr,33,seen);throw 1;}catch(const std::runtime_error&){assertions++;}
 std::cout<<assertions<<" actual native destination/outline assertions PASS; PDFium parser/action peers controlled"<<std::endl;
}
'''.replace('/*ACTUAL_OUTLINE*/',outlines)
        with tempfile.TemporaryDirectory(prefix='pdfium-destinations-') as temp:
            folder=Path(temp);file=folder/'dest.cpp';output=folder/('dest.exe' if os.name=='nt' else 'dest')
            def run(body):
                file.write_text(cpp.replace('/*ACTUAL_DESTINATION_AND_HELPERS*/',body),encoding='utf-8')
                subprocess.run([compiler,'-std=c++17','-O2',str(file),'-o',str(output)],check=True)
                return subprocess.run([str(output)],capture_output=True,text=True)
            good=run(helpers);self.assertEqual(good.returncode,0,good.stderr);print(good.stdout.strip())
            old='if(page<0 || page>=pageCount)return unsupported("Unresolved original page destination");'
            self.assertEqual(helpers.count(old),1)
            mutations=(
                ('document-fatal baseline','require(page>=0 && page<pageCount,"Invalid destination original page");'),
                ('guessed page0','if(page<0 || page>=pageCount)page=0;'),
                ('upper-bound omission','if(page<0)return unsupported("Unresolved original page destination");'),
            )
            for label,replacement in mutations:
                result=run(helpers.replace(old,replacement,1));self.assertNotEqual(result.returncode,0,label)
            print('Fatal-baseline red->green and3 compiled destination mutants rejected')


if __name__=='__main__':unittest.main()
