// Isolated desktop proof. No device, upload, write endpoint or arbitrary PDF route.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {canonicalCoreModules} from './canonical-core.mjs';
const root=path.dirname(fileURLToPath(import.meta.url));
const vendor=fs.realpathSync(process.argv[2] ?? '');
const fixture=fs.realpathSync(process.argv[3] ?? '');
const port=Number(process.argv[4] ?? 49731);
if(!Number.isInteger(port) || port<1024 || port>65535) throw Error('Invalid local port');
const lock=JSON.parse(fs.readFileSync(path.join(root,'pdfjs.lock.json'),'utf8'));
const pkg=JSON.parse(fs.readFileSync(path.join(vendor,'package.json'),'utf8'));
if(pkg.name!==lock.name || pkg.version!==lock.version) throw Error('Pinned vendor identity mismatch');
const archive=path.join(path.dirname(vendor),`pdfjs-dist-${lock.version}.tgz`);
if(`sha512-${crypto.createHash('sha512').update(fs.readFileSync(archive)).digest('base64')}`!==lock.integrity) throw Error('Vendor archive integrity mismatch');
const fixtureInfo=JSON.parse(fs.readFileSync(fixture.replace(/\.pdf$/,'.json'),'utf8'));
const pdf=fs.readFileSync(fixture);
const sha256=crypto.createHash('sha256').update(pdf).digest('hex');
if(!fixtureInfo.disposable || fixtureInfo.sha256!==sha256 || pdf.length>20000000) throw Error('Only the verified bounded disposable fixture may be served');
const core=canonicalCoreModules(path.resolve(root,'../..'));
const csp="default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self' blob: data:; img-src 'self' blob: data:; connect-src 'self'; worker-src 'self' blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const types={'.html':'text/html','.css':'text/css','.mjs':'text/javascript','.js':'text/javascript','.pdf':'application/pdf','.json':'application/json','.wasm':'application/wasm','.bcmap':'application/octet-stream','.ttf':'font/ttf','.otf':'font/otf','.pfb':'application/octet-stream'};
const server=http.createServer((req,res)=> {
  res.setHeader('Content-Security-Policy',csp);res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Cache-Control','no-store');
  if(!['GET','HEAD'].includes(req.method)) {res.writeHead(405);res.end();return;}
  try {
    const url=new URL(req.url,'http://127.0.0.1');
    if(url.search) throw Error('Query routes disabled');
    const name=decodeURIComponent(url.pathname);
    let data,type;
    if(name==='/document.pdf') {data=pdf;type=types['.pdf'];}
    else if(name==='/source.json') {data=Buffer.from(JSON.stringify({sha256,pages:fixtureInfo.pages,disposable:true,engineVersion:lock.version}));type=types['.json'];}
    else if(name==='/core/layout.mjs') {data=Buffer.from(core.layout);type=types['.mjs'];}
    else if(name==='/core/keys.mjs') {data=Buffer.from(core.keys);type=types['.mjs'];}
    else if(name==='/favicon.ico') {res.writeHead(204);res.end();return;}
    else if(['/','/viewer.mjs','/viewer.css','/destinations.mjs'].includes(name)) {const leaf=name==='/'?'viewer.html':name.slice(1);data=fs.readFileSync(path.join(root,leaf));type=types[path.extname(leaf)];}
    else if(name.startsWith('/pdfjs/')) {
      const target=fs.realpathSync(path.resolve(vendor,name.slice(7)));
      if(!target.startsWith(vendor+path.sep) || !fs.statSync(target).isFile() || !types[path.extname(target)]) throw Error('Vendor route rejected');
      data=fs.readFileSync(target);type=types[path.extname(target)];
    } else {res.writeHead(404);res.end();return;}
    if(req.headers.range && name==='/document.pdf') {
      const match=/^bytes=(\d+)-(\d*)$/.exec(req.headers.range);
      const start=match?Number(match[1]):NaN,end=match && match[2]?Math.min(Number(match[2]),data.length-1):data.length-1;
      if(!Number.isSafeInteger(start) || start<0 || start> end || end>=data.length) {res.writeHead(416);res.end();return;}
      res.setHeader('Content-Range',`bytes ${start}-${end}/${data.length}`);data=data.subarray(start,end+1);res.statusCode=206;
    }
    res.setHeader('Content-Type',type);res.setHeader('Content-Length',data.length);res.setHeader('Accept-Ranges','bytes');
    res.end(req.method==='HEAD'?undefined:data);
  } catch(_) {res.writeHead(403);res.end();}
});
server.listen(port,'127.0.0.1',()=>console.log(`T018 loopback-only proof http://127.0.0.1:${port} sourceSHA256=${sha256} pid=${process.pid}`));
for(const signal of ['SIGINT','SIGTERM']) process.on(signal,()=>server.close(()=>process.exit(0)));
