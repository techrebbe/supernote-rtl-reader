// Disposable-only public PDFium JNI proof. No writer/save/action-execution API.
#include <jni.h>
#include <fpdfview.h>
#include <fpdf_text.h>
#include <fpdf_doc.h>
#include <algorithm>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace {
constexpr int kPixels=6000000, kChars=20000, kItems=1000;
std::mutex mutex;
std::vector<unsigned char> bytes;
FPDF_DOCUMENT document=nullptr;
bool initialized=false;
int pageCount=0;
uint64_t nextSession=0,currentSession=0;
void require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
void session(jlong token){require(document && token>0 && static_cast<uint64_t>(token)==currentSession,"Closed/stale document session");}
struct Page {
  FPDF_PAGE value;
  explicit Page(int index):value(nullptr){
    require(document && index>=0 && index<pageCount,"Closed/invalid original page");
    value=FPDF_LoadPage(document,index);require(value,"Page load failed");
  }
  ~Page(){if(value)FPDF_ClosePage(value);}
  Page(const Page&)=delete;Page& operator=(const Page&)=delete;
};
struct Text {
  FPDF_TEXTPAGE value;
  explicit Text(FPDF_PAGE page):value(FPDFText_LoadPage(page)){require(value,"Text load failed");}
  ~Text(){if(value)FPDFText_ClosePage(value);}
};
struct Bitmap {
  FPDF_BITMAP value;
  Bitmap(int w,int h):value(FPDFBitmap_Create(w,h,0)){require(value,"Bitmap allocation failed");}
  ~Bitmap(){if(value)FPDFBitmap_Destroy(value);}
};
void close(){
  if(document)FPDF_CloseDocument(document);
  document=nullptr;pageCount=0;currentSession=0;bytes.clear();
  if(initialized)FPDF_DestroyLibrary();initialized=false;
}
void exception(JNIEnv* env,const char* message){
  if(!env->ExceptionCheck())env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),message);
}
std::string number(double value){
  require(std::isfinite(value) && std::abs(value)<=1000000,"Native numeric bound");
  std::ostringstream out;out.precision(12);out<<value;return out.str();
}
std::string unicode(uint32_t value){
  require(value<=0x10ffff,"Invalid Unicode value");
  auto unit=[](uint32_t u){const char* hex="0123456789abcdef";std::string s="\\u0000";
    for(int i=0;i<4;i++)s[5-i]=hex[(u>>(i*4))&15];return s;};
  if(value<=0xffff)return unit(value);
  value-=0x10000;return unit(0xd800+(value>>10))+unit(0xdc00+(value&1023));
}
std::string ascii(const std::string& input){
  std::string out="\"";for(unsigned char ch:input)out+=unicode(ch);return out+"\"";
}
std::string unsupported(const std::string& reason){return "{\"kind\":\"unsupported\",\"reason\":"+ascii(reason)+"}";}
std::string destination(FPDF_DEST dest){
  if(!dest)return unsupported("No supported destination");
  int page=FPDFDest_GetDestPageIndex(document,dest);require(page>=0 && page<pageCount,"Invalid destination original page");
  unsigned long count=0;FS_FLOAT values[4]={};
  auto mode=FPDFDest_GetView(dest,&count,values);require(count<=4,"Destination parameter bound");
  std::string prefix="{\"kind\":\"internal\",\"pageIndex\":"+std::to_string(page);
  if(mode==PDFDEST_VIEW_FIT && count==0)return prefix+",\"mode\":\"Fit\"}";
  if(mode==PDFDEST_VIEW_XYZ){
    FPDF_BOOL hasX=0,hasY=0,hasZoom=0;FS_FLOAT x=0,y=0,zoom=0;
    require(FPDFDest_GetLocationInPage(dest,&hasX,&hasY,&hasZoom,&x,&y,&zoom),"Invalid XYZ destination");
    require(!hasZoom || zoom>=0,"Negative zoom");
    return prefix+",\"mode\":\"XYZ\",\"left\":"+(hasX?number(x):"null")+",\"top\":"+(hasY?number(y):"null")+",\"zoom\":"+(hasZoom?number(zoom):"null")+"}";
  }
  return unsupported("Destination mode not implemented by diagnostic");
}
std::string action(FPDF_DEST dest,FPDF_ACTION value){
  if(value){
    auto type=FPDFAction_GetType(value);
    if(type==PDFACTION_GOTO)return destination(FPDFAction_GetDest(document,value));
    if(type==PDFACTION_URI){
      auto len=FPDFAction_GetURIPath(document,value,nullptr,0);require(len>0 && len<=4096,"URI bound");
      std::vector<char> raw(len,0);require(FPDFAction_GetURIPath(document,value,raw.data(),len)==len,"URI snapshot mismatch");
      std::string uri(raw.data(),len-1),scheme=uri.substr(0,uri.find(':'));
      std::transform(scheme.begin(),scheme.end(),scheme.begin(),[](unsigned char c){return std::tolower(c);});
      if((scheme!="http" && scheme!="https") || uri.find("://")!=scheme.size())return unsupported("Unsafe URI scheme");
      auto hostStart=scheme.size()+3,hostEnd=uri.find_first_of("/?#",hostStart);
      auto host=uri.substr(hostStart,hostEnd==std::string::npos?std::string::npos:hostEnd-hostStart);
      if(host.empty() || host.find('@')!=std::string::npos || std::any_of(uri.begin(),uri.end(),[](unsigned char c){return c<33 || c>126 || c=='\\';}))return unsupported("Unsafe/unsupported URI");
      // Even confirmed diagnostic links cannot dispatch an external intent.
      return "{\"kind\":\"external-blocked\",\"uri\":"+ascii(uri)+"}";
    }
    return unsupported("Script/Launch/remote/unknown action disabled");
  }
  return destination(dest);
}
std::string deviceRect(FPDF_PAGE page,int w,int h,double l,double b,double r,double t){
  int minX=INT32_MAX,minY=INT32_MAX,maxX=INT32_MIN,maxY=INT32_MIN;
  require(std::isfinite(l) && std::isfinite(b) && std::isfinite(r) && std::isfinite(t),"Nonfinite source rectangle");
  for(double x:{l,r})for(double y:{b,t}){
    int dx=0,dy=0;require(FPDF_PageToDevice(page,0,0,w,h,0,x,y,&dx,&dy),"Source-to-view mapping failed");
    minX=std::min(minX,dx);minY=std::min(minY,dy);maxX=std::max(maxX,dx);maxY=std::max(maxY,dy);
  }
  minX=std::clamp(minX,0,w);minY=std::clamp(minY,0,h);maxX=std::clamp(maxX,0,w);maxY=std::clamp(maxY,0,h);
  return "["+std::to_string(minX)+","+std::to_string(minY)+","+std::to_string(maxX)+","+std::to_string(maxY)+"]";
}
bool cropRect(const FS_RECTF& crop,double& l,double& b,double& r,double& t){
  require(std::isfinite(l)&&std::isfinite(b)&&std::isfinite(r)&&std::isfinite(t),"Nonfinite hit rectangle");
  l=std::max(l,static_cast<double>(crop.left));b=std::max(b,static_cast<double>(crop.bottom));
  r=std::min(r,static_cast<double>(crop.right));t=std::min(t,static_cast<double>(crop.top));
  return l<r && b<t;
}
void bound(const std::string& text){require(text.size()<=2000000,"Diagnostic metadata byte bound");}
std::string outlines(FPDF_BOOKMARK parent,int depth,std::unordered_set<FPDF_BOOKMARK>& seen){
  require(depth<=32,"Outline depth bound");std::string out="[";bool comma=false;
  for(auto item=FPDFBookmark_GetFirstChild(document,parent);item;item=FPDFBookmark_GetNextSibling(document,item)){
    require(seen.size()<kItems && seen.insert(item).second,"Cyclic/large outline");
    auto len=FPDFBookmark_GetTitle(item,nullptr,0);require(len>=2 && len<=8192 && len%2==0,"Outline title size bound");
    std::vector<uint16_t> title(len/2);require(FPDFBookmark_GetTitle(item,title.data(),len)==len,"Outline title mismatch");
    if(comma)out+=",";comma=true;out+="{\"title\":\"";
    for(size_t i=0;i+1<title.size();i++)out+=unicode(title[i]);
    out+="\",\"destination\":"+action(FPDFBookmark_GetDest(document,item),FPDFBookmark_GetAction(item));
    out+=",\"children\":"+outlines(item,depth+1,seen)+"}";bound(out);
  }
  return out+"]";
}
void dimensions(int w,int h){require(w>0 && h>0 && static_cast<int64_t>(w)*h<=kPixels,"Bitmap allocation bound");}
}

extern "C" JNIEXPORT jlong JNICALL Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_open(JNIEnv* env,jclass,jbyteArray input){
  std::lock_guard<std::mutex> guard(mutex);
  if(document || initialized){exception(env,"Document already open");return 0;}
  try{
    require(input,"Missing fixture bytes");require(nextSession<INT64_MAX,"Session generation exhausted");auto len=env->GetArrayLength(input);
    require(len>0 && len<1000000,"Only bounded embedded fixture bytes allowed");bytes.resize(len);
    env->GetByteArrayRegion(input,0,len,reinterpret_cast<jbyte*>(bytes.data()));if(env->ExceptionCheck()){bytes.clear();return 0;}
    FPDF_InitLibrary();initialized=true;document=FPDF_LoadMemDocument64(bytes.data(),bytes.size(),nullptr);
    require(document,"Fixture load failed");pageCount=FPDF_GetPageCount(document);require(pageCount==4,"Expected exact four-page disposable fixture");currentSession=++nextSession;return currentSession;
  }catch(const std::exception& error){close();exception(env,error.what());return 0;}
}
extern "C" JNIEXPORT void JNICALL Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_close(JNIEnv*,jclass,jlong token){std::lock_guard<std::mutex> guard(mutex);if(token>0 && static_cast<uint64_t>(token)==currentSession)close();}
extern "C" JNIEXPORT jint JNICALL Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_count(JNIEnv* env,jclass,jlong token){std::lock_guard<std::mutex> guard(mutex);try{session(token);return pageCount;}catch(const std::exception& error){exception(env,error.what());return 0;}}
extern "C" JNIEXPORT jstring JNICALL Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_outline(JNIEnv* env,jclass,jlong token){
  std::lock_guard<std::mutex> guard(mutex);try{session(token);std::unordered_set<FPDF_BOOKMARK> seen;auto out=outlines(nullptr,0,seen);return env->NewStringUTF(out.c_str());}catch(const std::exception& error){exception(env,error.what());return nullptr;}
}
extern "C" JNIEXPORT jstring JNICALL Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_model(JNIEnv* env,jclass,jlong token,jint index,jint w,jint h){
  std::lock_guard<std::mutex> guard(mutex);try{
    session(token);dimensions(w,h);Page page(index);Text text(page.value);auto count=FPDFText_CountChars(text.value);require(count>=0 && count<=kChars,"Text count bound");
    auto width=FPDF_GetPageWidthF(page.value),height=FPDF_GetPageHeightF(page.value);require(width>0 && height>0,"Invalid page size");
    FS_RECTF crop{};require(FPDF_GetPageBoundingBox(page.value,&crop),"Missing crop authority");
    std::string out="{\"session\":"+std::to_string(currentSession)+",\"pageIndex\":"+std::to_string(index)+",\"width\":"+number(width)+",\"height\":"+number(height)+",\"renderWidth\":"+std::to_string(w)+",\"renderHeight\":"+std::to_string(h)+",\"crop\":["+number(crop.left)+","+number(crop.bottom)+","+number(crop.right)+","+number(crop.top)+"],\"text\":\"";
    std::vector<int> starts(count),ends(count);int utf16=0;
    for(int i=0;i<count;i++){auto u=FPDFText_GetUnicode(text.value,i);starts[i]=utf16;utf16+=u>0xffff?2:1;ends[i]=utf16;out+=unicode(u);}
    out+="\",\"chars\":[";bool comma=false;std::string gap;
    for(int i=0;i<count;i++){
      double l=0,r=0,b=0,t=0;bool box=FPDFText_GetCharBox(text.value,i,&l,&r,&b,&t);
      auto u=FPDFText_GetUnicode(text.value,i);bool separator=u==32 || u==9 || u==13 || u==10;
      if(!box || !cropRect(crop,l,b,r,t)){
        // Generated/missing-box separators retain CR/LF spacing; actual hidden
        // source glyphs (including cropped source spaces) cannot bridge a copy.
        if(separator && (!box || FPDFText_IsGenerated(text.value,i)==1))gap+=unicode(u);else gap.clear();
        continue;
      }
      if(comma)out+=",";comma=true;out+="{\"index\":"+std::to_string(i)+",\"textStart\":"+std::to_string(starts[i])+",\"textEnd\":"+std::to_string(ends[i])+",\"gapBefore\":\""+gap+"\",\"rect\":"+deviceRect(page.value,w,h,l,b,r,t)+"}";gap.clear();bound(out);
    }
    out+="],\"links\":[";int offset=0,items=0;FPDF_LINK link=nullptr;comma=false;
    while(FPDFLink_Enumerate(page.value,&offset,&link)){
      require(++items<=kItems,"Link count bound");FS_RECTF rect{};require(FPDFLink_GetAnnotRect(link,&rect),"Missing link rectangle");
      double l=rect.left,b=rect.bottom,r=rect.right,t=rect.top;if(!cropRect(crop,l,b,r,t))continue;
      if(comma)out+=",";comma=true;out+="{\"rect\":"+deviceRect(page.value,w,h,l,b,r,t)+",\"action\":"+action(FPDFLink_GetDest(document,link),FPDFLink_GetAction(link))+"}";bound(out);
    }
    out+="]}";bound(out);return env->NewStringUTF(out.c_str());
  }catch(const std::exception& error){exception(env,error.what());return nullptr;}
}
extern "C" JNIEXPORT jdoubleArray JNICALL Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_size(JNIEnv* env,jclass,jlong token,jint index){
  std::lock_guard<std::mutex> guard(mutex);try{session(token);Page page(index);double values[]={FPDF_GetPageWidthF(page.value),FPDF_GetPageHeightF(page.value)};require(std::isfinite(values[0]) && std::isfinite(values[1]) && values[0]>0 && values[1]>0 && values[0]<=20000 && values[1]<=20000,"Page size bound");auto out=env->NewDoubleArray(2);if(out)env->SetDoubleArrayRegion(out,0,2,values);return out;}catch(const std::exception& error){exception(env,error.what());return nullptr;}
}
extern "C" JNIEXPORT jdoubleArray JNICALL Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_point(JNIEnv* env,jclass,jlong token,jint index,jint w,jint h,jdouble x,jdouble y,jboolean inverse){
  std::lock_guard<std::mutex> guard(mutex);try{session(token);dimensions(w,h);require(std::isfinite(x)&&std::isfinite(y)&&std::abs(x)<=1000000&&std::abs(y)<=1000000,"Point bound");Page page(index);double values[2]={};
    if(inverse){require(FPDF_DeviceToPage(page.value,0,0,w,h,0,static_cast<int>(std::round(x)),static_cast<int>(std::round(y)),&values[0],&values[1]),"View-to-source failed");}
    else{int dx=0,dy=0;require(FPDF_PageToDevice(page.value,0,0,w,h,0,x,y,&dx,&dy),"Source-to-view failed");values[0]=dx;values[1]=dy;}
    require(std::isfinite(values[0])&&std::isfinite(values[1]),"Point mapping nonfinite");auto out=env->NewDoubleArray(2);if(out)env->SetDoubleArrayRegion(out,0,2,values);return out;
  }catch(const std::exception& error){exception(env,error.what());return nullptr;}
}
extern "C" JNIEXPORT jintArray JNICALL Java_com_techrebbe_rtl_pdfiumprobe_NativeCore_render(JNIEnv* env,jclass,jlong token,jint index,jint w,jint h){
  std::lock_guard<std::mutex> guard(mutex);try{session(token);dimensions(w,h);Page page(index);Bitmap bitmap(w,h);
    require(FPDFBitmap_FillRect(bitmap.value,0,0,w,h,0xffffffff),"Bitmap fill failed");FPDF_RenderPageBitmap(bitmap.value,page.value,0,0,w,h,0,FPDF_ANNOT);
    auto stride=FPDFBitmap_GetStride(bitmap.value);auto* source=static_cast<uint8_t*>(FPDFBitmap_GetBuffer(bitmap.value));require(source && stride>=w*4 && stride<=w*4+64,"Invalid bitmap buffer");
    std::vector<jint> pixels(static_cast<size_t>(w)*h);
    for(int y=0;y<h;y++)for(int x=0;x<w;x++){auto* p=source+y*stride+x*4;pixels[static_cast<size_t>(y)*w+x]=static_cast<jint>(0xff000000u|static_cast<uint32_t>(p[2])<<16|static_cast<uint32_t>(p[1])<<8|p[0]);}
    auto out=env->NewIntArray(pixels.size());if(out)env->SetIntArrayRegion(out,0,pixels.size(),pixels.data());return out;
  }catch(const std::exception& error){exception(env,error.what());return nullptr;}
}
