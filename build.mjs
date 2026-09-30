// Encrypts ../source/summary.html into index.html so the public page holds only ciphertext.
// Usage: node build.mjs            (prompts for the password; must match the existing one)
//        node build.mjs --new-password   (skip the match check to rotate the password)
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const SRC = join(here, '..', 'source', 'summary.html');
const OUT = join(here, 'index.html');
const ITER = 600000;
// SHA-256 of the password buyers were already given.
const KNOWN = 'c63496edded82f5930cbf8893895280a9423a9e8de0ca35a1740835532038954';

function askHidden(q) {
  return new Promise((resolve) => {
    const { stdin, stdout } = process;
    stdout.write(q);
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    let s = '';
    stdin.on('data', function on(ch) {
      if (ch === '\r' || ch === '\n' || ch === '\u0004') {
        stdin.setRawMode(false); stdin.pause(); stdin.off('data', on); stdout.write('\n'); resolve(s);
      } else if (ch === '\u0003') { stdout.write('\n'); process.exit(1); }
      else if (ch === '\u007f' || ch === '\b') s = s.slice(0, -1);
      else s += ch;
    });
  });
}

const src = readFileSync(SRC, 'utf8');
const start = src.indexOf('<body>') + '<body>'.length;
const end = src.indexOf('<div id="gate"');
const scriptStart = src.indexOf('<script>', end);
const scriptEnd = src.indexOf('</script>', scriptStart) + '</script>'.length;
if (start < 6 || end < 0 || scriptStart < 0) throw new Error('source layout changed; update build.mjs');
const secret = src.slice(start, end);
const gate = src.slice(end, scriptStart);

const pw = process.stdin.isTTY
  ? await askHidden('Page password: ')
  : readFileSync(0, 'utf8').replace(/\r?\n$/, '');
if (!process.argv.includes('--new-password') && createHash('sha256').update(pw).digest('hex') !== KNOWN) {
  console.error('That is not the current password. Re-run, or pass --new-password to change it.');
  process.exit(1);
}

const enc = new TextEncoder();
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(secret)));
const b64 = (u) => Buffer.from(u).toString('base64');

const script = `<script>
(function(){
var S='${b64(salt)}',V='${b64(iv)}',C='${b64(ct)}',N=${ITER},K='zn_k';
var gate=document.getElementById('gate'),form=document.getElementById('gateform'),err=document.getElementById('g_err'),btn=form.querySelector('button');
function u(b){return Uint8Array.from(atob(b),function(c){return c.charCodeAt(0)})}
function b(a){return btoa(String.fromCharCode.apply(null,new Uint8Array(a)))}
async function open(key){var p=await crypto.subtle.decrypt({name:'AES-GCM',iv:u(V)},key,u(C));
  document.getElementById('vault').outerHTML=new TextDecoder().decode(p);gate.hidden=true;document.body.classList.remove('locked')}
async function fromRaw(r){return crypto.subtle.importKey('raw',u(r),'AES-GCM',true,['decrypt'])}
async function lock(){gate.hidden=false;document.body.classList.add('locked');
  form.addEventListener('submit',async function(e){e.preventDefault();err.hidden=true;btn.disabled=true;
    try{var base=await crypto.subtle.importKey('raw',new TextEncoder().encode(document.getElementById('g_pw').value),'PBKDF2',false,['deriveKey']);
      var key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:u(S),iterations:N,hash:'SHA-256'},base,{name:'AES-GCM',length:256},true,['decrypt']);
      await open(key);try{localStorage.setItem(K,S+':'+b(await crypto.subtle.exportKey('raw',key)))}catch(x){}}
    catch(x){err.hidden=false}btn.disabled=false});}
var saved=null;try{saved=localStorage.getItem(K)}catch(e){}
if(saved&&saved.indexOf(S+':')===0){fromRaw(saved.slice(S.length+1)).then(open).catch(lock)}else{lock()}
})();
</script>`;

const out = src.slice(0, start) + '<div id="vault"></div>\n' + gate + script + src.slice(scriptEnd);
writeFileSync(OUT, out.replace('<meta charset="utf-8">', '<meta charset="utf-8"><meta name="robots" content="noindex,nofollow">'));
console.log(`Wrote ${OUT} (${out.length} bytes, content encrypted).`);
