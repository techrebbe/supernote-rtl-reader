import fs from 'node:fs';
import path from 'node:path';
// Read the existing original-page pairing and key controller; never fork them.
export function canonicalCoreModules(repo) {
  const app=fs.readFileSync(path.join(repo,'overlay/App.js'),'utf8').replace(/\r\n/g,'\n');
  const first=app.indexOf('function normalizePage('),last=app.indexOf('function viewModeLabel(');
  if(first<0 || last<=first || app.indexOf('function normalizePage(',first+1)!==-1) throw Error('Canonical layout markers missing/ambiguous');
  const keySource=fs.readFileSync(path.join(repo,'overlay/pageTurnerKeys.js'),'utf8');
  return {
    layout:app.slice(first,last)+'\nexport {getSpreadPair,getVisualSpread};',
    keys:'const module={exports:{}};\n'+keySource+'\nexport {createPageTurnerKeys};',
  };
}
