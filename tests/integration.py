"""Verify HTTP, authenticated encrypted delivery, and append-only writes using generated fixtures."""
import base64
import hashlib
import hmac
import http.client
import io
import json
import os
import re
import shlex
import shutil
from pathlib import Path
import socket
import sqlite3
import subprocess
import threading
import time
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = Path(__file__).resolve().parents[1]
GD = Path(os.environ.get('KEYS_GD') or shutil.which('gd') or ROOT/'.runtime/gd/gd').resolve()
TEST_ENTRANCE_PASSWORD = 'fixture web entrance password'
RUN = ROOT/'tmp'/('integration-'+uuid.uuid4().hex)
RUN.mkdir(parents=True,mode=0o700)
os.umask(0o077)
checks=0
cookie=''
csrf=''
server=None

def check(ok,label):
 global checks
 if not ok: raise AssertionError(label)
 checks+=1; print('PASS',label)

def write_json(path,data): path.write_text(json.dumps(data))
with socket.socket() as s:
 s.bind(('127.0.0.1',0));port=s.getsockname()[1]
subprocess.run([str(ROOT/'keys'),'init',str(RUN)], input=TEST_ENTRANCE_PASSWORD+'\n', text=True, cwd=ROOT, env=dict(os.environ, KEYS_GD=str(GD)), capture_output=True, check=True)
devices=[{'ip':'127.0.0.1','name':'Test'}]
legacy_key=base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
(RUN/'FAMILY-RULE.md').write_text('K='+legacy_key+'；legacy fixture rule\n')
write_json(RUN/'config.json',{'bind':'127.0.0.1','port':port,'hosts':['localhost','127.0.0.1'],'devices':devices})

def request(method,path,data=None,headers=None):
 c=http.client.HTTPConnection('localhost',port,timeout=35)
 h={'Content-Type':'application/json','X-Keys-CSRF':csrf,'Cookie':cookie};h.update(headers or {})
 c.request(method,path,None if data is None else json.dumps(data).encode(),h)
 r=c.getresponse(); result=(r.status,r.read(),dict(r.getheaders()));c.close();return result

def payload(method,path,data=None,headers=None):
 status,raw,h=request(method,path,data,headers);return status,json.loads(raw)

def rpc(name,args=None):
 response=rpc_response(name,args)
 return json.loads(response['result']['content'][0]['text'])

def rpc_response(name,args=None):
 return payload('POST','/mcp',{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args or {}}},{'Cookie':'','X-Keys-CSRF':''})[1]

def start():
 p=subprocess.Popen([str(GD),'serve','server.gd',str(RUN)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 for _ in range(100):
  if p.poll() is not None: raise AssertionError('server exited before readiness')
  try:
   if request('GET','/api/status')[0]==200:return p
  except OSError:pass
  time.sleep(.05)
 p.terminate();raise AssertionError('readiness timeout')

def append(url,target,key,openssl=None):
 env=dict(os.environ,K=key)
 if openssl:
  folder=RUN/'bin';folder.mkdir(exist_ok=True)
  link=folder/'openssl'
  if not link.exists():link.symlink_to(openssl)
  env['PATH']=str(folder)+os.pathsep+env.get('PATH','')
 return subprocess.run(['sh',str(ROOT/'append-env.sh'),url,str(target)],env=env,cwd=ROOT,text=True,capture_output=True,timeout=10)

try:
 server=start()
 restart_ticket=rpc('begin_intake',{'title':'Restart fixture','variable':'RESTART_TEST'})
 restart_path='/intake/'+restart_ticket['id']
 old_info=payload('GET',restart_path+'/info')[1]
 server.terminate();server.communicate(timeout=5);server=None
 server=start()
 fresh_info=payload('GET',restart_path+'/info')[1]
 check(old_info['csrf']==fresh_info['csrf'] and fresh_info['status']=='waiting','intake nonce and pending transaction survive a server restart')
 status,error=payload('POST',restart_path,{'value':'fixture-restart'},{'X-Intake-CSRF':'obsolete-process-nonce'})
 check(status==403 and error['code']=='INTAKE_NONCE_STALE','obsolete confirmation is rejected with a recoverable error code')
 check(payload('POST',restart_path,{'value':'fixture-restart'},{'X-Intake-CSRF':old_info['csrf']})[0]==200,'an already-open form can submit with its original nonce after restart')
 check(payload('GET','/api/status')[1]['authenticated'] is False,'web entrance requires login')
 check(request('GET','/api/items')[0]==401,'anonymous browser cannot list the vault')
 check(request('GET','/api/family-rule')[0]==401,'family shared secret is hidden before login')
 check(all(request('GET',path)[0]==401 for path in ('/api/family-key','/api/family-skill')),'family setup downloads require login')
 check(request('POST','/api/family-invite',{})[0]==401,'issuing family invitations requires login')
 status,lan_archive,_=request('GET','/assets/family-keys-skill.zip')
 check(status==200,'skill archive is available over LAN without a login')
 check(payload('POST','/api/login',{'password':'wrong-test-password'})[0]==401,'wrong entrance password is refused')
 status,_,headers=request('POST','/api/login',{'password':TEST_ENTRANCE_PASSWORD})
 cookie=headers['Set-Cookie'].split(';',1)[0]
 check(status==200 and 'HttpOnly' in headers['Set-Cookie'] and 'Secure' not in headers['Set-Cookie'],'HTTP login creates the intended same-site cookie')
 csrf=payload('GET','/api/status')[1]['csrf']
 network_update={'devices':devices,'allowed_networks':['192.0.2.*','10.0.0.0/24']}
 check(request('POST','/api/devices',network_update,{'Cookie':''})[0]==401,'changing allowed networks requires login')
 check(request('POST','/api/devices',dict(network_update,allowed_networks=['192.168.500.0/24']))[0]==400,'invalid network is rejected')
 for bad in ['192.168.050.0/24','0.0.0.0/0','192.0.2.0//24','http://192.0.2.0/24',None]:
  check(request('POST','/api/devices',dict(network_update,allowed_networks=['192.0.2.0/24',bad]))[0]==400,'malformed network entry is rejected')
 for bad in ['127.00.0.1','127.0.0.1/32','127.0.0.1:8080','localhost','::1%lo0',None]:
  check(request('POST','/api/devices',dict(network_update,devices=devices+[{'ip':bad,'name':'Bad'}]))[0]==400,'malformed fixed IP is rejected')
 status,updated=payload('POST','/api/devices',network_update)
 networks=['192.0.2.0/24','10.0.0.0/24']
 check(status==200 and updated['allowed_networks']==networks and json.loads((RUN/'config.json').read_text())['allowed_networks']==networks,'multiple networks are normalized and persisted')
 check(request('POST','/api/devices',dict(network_update,devices=[]))[0]==400 and payload('GET','/api/devices')[1]['allowed_networks']==networks,'network settings cannot lock out the caller')
 check(payload('POST','/api/devices',dict(network_update,allowed_networks=[]))[1]['allowed_networks']==[],'empty ranges allow fixed IPs only')
 rule=payload('GET','/api/family-rule')[1]['rule']
 key=re.search(r'^FAMILY_KEYS_K=([A-Za-z0-9_-]+)$',rule,re.M)[1]
 check(key==legacy_key,'updated setup text preserves the existing shared key')
 status,keyfile,headers=request('GET','/api/family-key')
 check(status==200 and keyfile==f'FAMILY_KEYS_K={key}\n'.encode() and 'family-keys.env' in headers['Content-Disposition'],'shared key downloads separately as an env file')
 status,archive,headers=request('GET','/api/family-skill')
 check(status==200 and 'family-keys-skill.zip' in headers['Content-Disposition'],'skill archive downloads after login')
 check(lan_archive==archive,'LAN skill archive is the same secret-free package')
 with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
  files={entry.filename for entry in bundle.infolist() if not entry.is_dir()}
  check(files=={'family-keys/SKILL.md','family-keys/scripts/append-env.sh','family-keys/scripts/register-env.sh','family-keys/scripts/setup-key.sh'} and all(key.encode() not in bundle.read(name) for name in files),'skill package contains only instructions and helpers, never the shared key')
  bundle.extractall(RUN/'skill')
 endpoint='/api/family-distribution'
 check(request('GET',endpoint,headers={'Cookie':''})[0]==401,'distribution source requires a login')
 dist=payload('GET',endpoint)[1]
 edited_distribution=dict(dist,skill=dist['skill']+'\nCustom test instructions.\n',guide='Fixture setup\n'+dist['guide'])
 check(request('POST',endpoint,edited_distribution,{'X-Keys-CSRF':'wrong'})[0]==403,'editing distribution requires CSRF')
 check(request('POST',endpoint,dict(edited_distribution,guide='{{MCP_URL}}'))[0]==400 and request('POST',endpoint,dict(edited_distribution,skill='Invalid Markdown'))[0]==400,'invalid guide placeholders and skill frontmatter are rejected')
 check(request('POST',endpoint,dict(edited_distribution,skill=dist['skill']+'\n'+key))[0]==400,'the shared key cannot be added to the distributed skill')
 status,distribution_saved=payload('POST',endpoint,edited_distribution)
 check(status==200 and distribution_saved['guide']==edited_distribution['guide'] and distribution_saved['skill']==edited_distribution['skill'],'distribution stores the edited guide and skill')
 with zipfile.ZipFile(io.BytesIO(request('GET','/assets/family-keys-skill.zip')[1])) as bundle:
  check(bundle.read('family-keys/SKILL.md').decode()==distribution_saved['skill'],'skill ZIP immediately uses the edited Markdown')
 check(request('POST',endpoint,edited_distribution)[0]==409,'stale edits cannot overwrite newer distribution changes')
 check(request('POST','/api/family-invite',{}, {'X-Keys-CSRF':'wrong'})[0]==403,'issuing a family invitation requires the session CSRF token')
 status,invite=payload('POST','/api/family-invite',{})
 check(status==200 and key not in invite['instructions'],'copyable invitation does not expose the shared key')
 check(invite['instructions'].startswith('Fixture setup\n') and invite['url'] in invite['instructions'] and f'http://localhost:{port}/mcp' in invite['instructions'] and f'http://localhost:{port}/assets/family-keys-skill.zip' in invite['instructions'],'invitations render the edited guide with live URLs')
 from urllib.parse import urlsplit
 parsed=urlsplit(invite['url']); proof_header='X-Keys-Invite-Proof'
 guest={'Cookie':'','X-Keys-CSRF':''}
 check(request('GET',parsed.path,headers=guest)[0] in (404,405),'a link preview cannot consume an invitation')
 check(request('POST',parsed.path,{},guest)[0]==403,'an invitation identifier alone cannot consume the key')
 setup=RUN/'skill/family-keys/scripts/setup-key.sh'
 dest=RUN/'invite-recipient/key.env'
 setup_env=dict(os.environ,FAMILY_KEYS_KEY_FILE=str(dest))
 p=subprocess.run(['sh',str(setup),invite['url']],env=setup_env,cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode==0 and p.stdout.strip()=='OK' and dest.read_bytes().strip()==keyfile.strip() and dest.stat().st_mode&0o777==0o600,'invitation alone provisions the shared key privately')
 proof=hashlib.sha256(f'FK1-INVITE-PROOF:{parsed.path.rsplit("/",1)[-1]}:{parsed.fragment}'.encode()).hexdigest()
 check(request('POST',parsed.path,{},dict(guest,**{proof_header:proof}))[0]==404,'a redeemed invitation cannot be used again')
 status,invite=payload('POST','/api/family-invite',{})
 parsed=urlsplit(invite['url'])
 proof=hashlib.sha256(f'FK1-INVITE-PROOF:{parsed.path.rsplit("/",1)[-1]}:{parsed.fragment}'.encode()).hexdigest()
 status,wire,_=request('POST',parsed.path,{},dict(guest,**{proof_header:proof}))
 check(status==200 and len(wire.splitlines())==3 and key.encode() not in wire,'invite redemption transmits authenticated ciphertext only')
 check((RUN/'FAMILY-RULE.md').stat().st_mode&0o777==0o600,'family rule file is private')
 for path in ['/','/assets/app.js','/assets/intake.js','/assets/style.css','/assets/append-env.sh']:
  status,_,headers=request('GET',path)
  check(status==200 and headers.get('Cache-Control')=='no-store','UI and short sh are served without caching: '+path)
 check(request('GET','/api/status',headers={'Host':'evil.invalid'})[0]==403,'unregistered host is refused')
 check(request('GET','/api/status',headers={'Origin':'http://evil.invalid'})[0]==403,'cross-origin access is refused')
 check(payload('GET','/api/status',headers={'X-Forwarded-For':'192.0.2.20'})[1]['device']['ip']=='127.0.0.1','proxy headers do not impersonate a device')
 check(request('POST','/api/items',{}, {'X-Keys-CSRF':'wrong'})[0]==403,'web saves require a CSRF header')
 fixture='# 偽のテストデータ\r\nTOKEN="fixture-only-Ω"\r\nMULTILINE="first\nsecond"\r\n'
 status,item=payload('POST','/api/items',{'name':'Discord 通知','aliases':'開発用','note':'家族でディスコードの通知に使う。','env_base64':base64.b64encode(fixture.encode()).decode()})
 check(status==200,'UTF-8 dotenv with CRLF can be registered')
 id=item['item']['id']
 edit_path='/api/items/'+id+'/reveal'
 _,editable=payload('POST',edit_path,{'fields':True})
 check(editable['fields']==[{'name':'TOKEN','value':'fixture-only-Ω'},{'name':'MULTILINE','value':'first\nsecond'}],'structured editor reads existing variables including multiline values')
 edit_data={'id':id,'revision':editable['item']['revision'],'name':editable['item']['name'],'aliases':editable['item']['aliases'],'note':editable['note'],'env_fields':editable['fields']}
 check(request('POST','/api/items',edit_data)[0]==200 and payload('POST',edit_path,{'fields':True})[1]['env']==fixture,'editing a note preserves the original dotenv bytes')
 check(request('POST','/api/items',edit_data)[0]==400,'a stale editor cannot overwrite a later save')
 for fields in [[],[{'name':'','value':'ignored'}],[{'name':'BAD-NAME','value':''}],[{'name':'DUP','value':'a'},{'name':'DUP','value':'b'}]]:
  check(request('POST','/api/items',{'name':'Invalid ENV fixture','env_fields':fields})[0]==400,'structured editor rejects missing, invalid, and duplicate ENV names')
 fields=[{'name':'TEST_VALUE','value':'space " quote \\ slash \n 日本語'},{'name':'TEST_EMPTY','value':''}]
 status,structured=payload('POST','/api/items',{'name':'Structured ENV fixture','env_fields':fields})
 check(status==200 and [payload('POST','/api/items/'+row['id']+'/reveal',{'fields':True})[1]['fields'][0] for row in structured['items']]==fields,'structured ENV values round-trip through the generated dotenv')
 fields=[{'name':'WEB_BATCH_A','value':'fixture-web-a'},{'name':'WEB_BATCH_B','value':'fixture-web-b'}]
 status,web_batch=payload('POST','/api/items',{'name':'Web batch fixture','split_env':True,'env_fields':fields})
 check(status==200 and [row['variables'] for row in web_batch['items']]==[['WEB_BATCH_A'],['WEB_BATCH_B']],'Web batch makes one record per ENV')
 fields=[{'name':'WEB_ROLLBACK','value':'fixture-rollback'},fields[0]]
 check(request('POST','/api/items',{'name':'Duplicate batch fixture','split_env':True,'env_fields':fields})[0]==400 and not rpc('search_env',{'query':'WEB_ROLLBACK'})['items'],'duplicate ENV rejects the entire batch')
 check('error' in rpc_response('begin_intake',{'title':'Duplicate MCP fixture','variable':'WEB_BATCH_A'}),'MCP intake rejects an existing ENV name')
 check('fixture-only' not in json.dumps(item),'save response contains metadata only')
 _,note=payload('POST','/api/items',{'name':'家族アカウント','owner':'Y','note':'パスワード fixture-note-password。サブアカウントの通知用。'})
 check(note['item']['owner']=='ALL','all family entries are shared without individual restrictions')
 import urllib.parse
 found=payload('GET','/api/items?q='+urllib.parse.quote('通知'))[1]['items']
 check(len(found)==2,'SQLite searches full Japanese notes')
 check('fixture-note-password' not in json.dumps(found),'search metadata does not reveal private notes')
 check(rpc('search_env',{'query':'サブアカウント'})=={'items':[{'id':note['item']['id'],'name':'家族アカウント'}]},'MCP searches by private note without exposing it or returning empty fields')
 status,revealed=payload('POST','/api/items/'+note['item']['id']+'/reveal',{})
 check(status==200 and 'fixture-note-password' in revealed['note'],'logged-in human can display a password')
 disk=(RUN/'keys.sqlite3').read_bytes()
 check(b'fixture-only' not in disk and b'fixture-note-password' not in disk,'SQLite persists encrypted prose and values')
 seed='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
 otp_input={'name':'OTP fixture','env':'TEST_PASSWORD=fixture-password\n','otp':{'variable':'TEST_PASSWORD','seed':seed}}
 check(request('POST','/api/items',dict(otp_input,otp={'variable':'WRONG','seed':seed}))[0]==400,'TOTP must reference an existing original ENV name')
 check(request('POST','/api/items',dict(otp_input,otp={'variable':'TEST_PASSWORD','seed':'invalid!'}))[0]==400,'invalid Base32 seed is rejected')
 _,otp_record=payload('POST','/api/items',{'name':otp_input['name'],'env':otp_input['env'],'note':'Original fixture note'})
 settings_path='/api/items/'+otp_record['item']['id']+'/otp/settings'
 check(request('POST',settings_path,otp_input['otp'],{'Cookie':''})[0]==401 and request('POST',settings_path,otp_input['otp'],{'X-Keys-CSRF':'wrong'})[0]==403,'dedicated TOTP settings require login and CSRF')
 status,otp_item=payload('POST',settings_path,otp_input['otp'])
 check(status==200 and otp_item['item']['otp_variable']=='TEST_PASSWORD' and seed not in json.dumps(otp_item),'stores optional TOTP beside original ENV without exposing its seed')
 otp_hit=rpc('search_env',{'query':'TEST_PASSWORD'})['items'][0]
 check(otp_hit=={'id':otp_item['item']['id'],'name':'OTP fixture','variables':['TEST_PASSWORD'],'has_totp':True},'search signals TOTP without returning a secret or redundant ENV name')
 status,legacy_otp=payload('POST','/api/items',{'name':'Legacy OTP fixture','env':'LEGACY_AUTH_USER=dummy-user\nLEGACY_AUTH_PASS=dummy-password\n','otp':{'variable':'LEGACY_AUTH_PASS','seed':seed}})
 legacy_otp_hit=rpc('search_env',{'query':'LEGACY_AUTH_PASS'})['items'][0]
 check(status==200 and legacy_otp_hit.get('has_totp') is True and legacy_otp_hit.get('totp_env')=='LEGACY_AUTH_PASS','search identifies the TOTP ENV for a legacy item with multiple variables')
 revealed=payload('POST','/api/items/'+otp_record['item']['id']+'/reveal',{})[1]
 check(revealed['note']=='Original fixture note' and revealed['env']==otp_input['env'] and seed not in json.dumps(revealed),'dedicated TOTP settings preserve existing credentials and notes')
 otp_id=otp_item['item']['id']
 otp_path='/api/items/'+otp_id+'/otp'
 def expected_codes():
  codes=[]
  for step in range(int(time.time())//30-1,int(time.time())//30+2):
   mac=hmac.new(base64.b32decode(seed),step.to_bytes(8,'big'),hashlib.sha1).digest(); offset=mac[-1]&15
   codes.append(f'{(int.from_bytes(mac[offset:offset+4],"big")&0x7fffffff)%1000000:06}')
  return codes
 _,shown=payload('POST',otp_path,{})
 check(shown['code'] in expected_codes() and 1<=shown['expires_in']<=30,'login UI receives a current standard TOTP and its expiry')
 otp_uri='otpauth://totp/Fixture%3ADemo?issuer=Fixture&secret='+seed
 check(request('POST',settings_path,{'variable':'TEST_PASSWORD','seed':otp_uri})[0]==200 and payload('POST',otp_path,{})[1]['code'] in expected_codes(),'pasteable otpauth URI sets the correct code')
 for bad_uri in [otp_uri.replace('/totp/','/hotp/'),otp_uri+'&digits=8',otp_uri+'&secret='+seed]:
  check(request('POST',settings_path,{'variable':'TEST_PASSWORD','seed':bad_uri})[0]==400,'unsupported or ambiguous OTP URL is rejected')
 qr_fixtures=json.loads((ROOT/'tests/fixtures/totp-qr.json').read_text())
 for index,matrix in enumerate(qr_fixtures):
  if index:
   # Damage one data module and rotate the larger symbol, exercising QR ECC.
   matrix[-1]=matrix[-1][:-1]+('0' if matrix[-1][-1]=='1' else '1')
   matrix=list(zip(*matrix[::-1]))
  scale=4
  width=len(matrix)*scale+73
  height=len(matrix)*scale+94
  gray=bytearray(b'\xff'*(width*height))
  for y,row in enumerate(matrix):
   line=bytes(0 if bit=='1' else 255 for bit in row)
   line=b''.join(bytes([sample])*scale for sample in line)
   for offset in range(scale):
    offset_in_image=(51+y*scale+offset)*width+19
    gray[offset_in_image:offset_in_image+len(line)]=line
  qr={'variable':'TEST_PASSWORD','qr':{'width':width,'height':height,'gray':base64.b64encode(gray).decode()}}
  status,qr_response=payload('POST',settings_path,qr)
  check(status==200 and seed not in json.dumps(qr_response) and payload('POST',otp_path,{})[1]['code'] in expected_codes(),'pasted TOTP QR stores the expected seed without returning it')
  check(request('POST',settings_path,qr,{'Cookie':''})[0]==401,'QR import is restricted to the logged-in editor')
 check(request('POST',settings_path,dict(qr,qr=dict(qr['qr'],width=999999)))[0]==400,'oversized QR raster is rejected')
 check(request('POST',otp_path,{}, {'Cookie':''})[0]==401,'browser TOTP reveal requires a session')
 prepared_otp=rpc('prepare_env',{'otp':'TEST_PASSWORD'})
 check(set(prepared_otp)=={'url'} and '/agent/otp/' in prepared_otp['url'],'MCP uses the original ENV name and returns only an encrypted delivery URL')
 status,otp_wire,_=request('GET','/agent/otp/'+otp_id)
 check(status==200 and len(otp_wire.splitlines())==3 and seed.encode() not in otp_wire,'TOTP delivery is authenticated ciphertext')
 p=subprocess.run(['sh',str(ROOT/'append-env.sh'),prepared_otp['url'],'-','otp','python3','-c','import sys; assert sys.stdin.read() in sys.argv[1:]',*expected_codes()],env=dict(os.environ,K=key),cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode==0 and p.stdout.strip()=='OK','local helper passes fresh OTP through stdin and prints only status')
 p=subprocess.run(['sh',str(ROOT/'append-env.sh'),rpc('prepare_env',{'id':otp_id})['url'],str(RUN/'.env.otp')],env=dict(os.environ,K=key),cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode==0 and (RUN/'.env.otp').read_text()=='\nTEST_PASSWORD=fixture-password\n','normal dotenv delivery excludes the TOTP seed and code')
 check(request('POST','/api/items',dict(otp_input,id=otp_id,otp={'variable':'TEST_PASSWORD','seed':''}))[0]==200 and payload('POST',otp_path,{})[1]['code'] in expected_codes(),'editing with a blank seed preserves the registered TOTP')
 skill={'name':'deploy-fixture','summary':'公開前の確認','body':'# Deploy\nCheck the target first.'}
 check(request('POST','/api/skills',skill,{'Cookie':''})[0]==401 and request('POST','/api/skills',dict(skill,name='../bad'))[0]==400,'skill writes require login and a valid name')
 check(request('POST','/api/skills',skill)[0]==200 and rpc('family_skills')=={'names':['deploy-fixture']},'family skills list returns names only')
 check(rpc('family_skills',{'query':'公開'})=={'items':[{'name':skill['name'],'summary':skill['summary']}]},'family skills search returns a summary without the body')
 skill_url=rpc('family_skills',{'name':skill['name']})['url']
 check(request('GET',urlsplit(skill_url).path,headers={'Cookie':''})[1].decode()==skill['body'],'exact skill selection reads one body through its URL')
 check(request('DELETE','/api/skills/deploy-fixture')[0]==200 and rpc('family_skills')=={'names':[]},'deleting a skill removes it from discovery')
 prepared=rpc('prepare_env',{'id':id})
 check(set(prepared)=={'url','script'} and key not in json.dumps(prepared),'MCP delivery returns just the encrypted payload and helper URLs')
 url=prepared['url']
 status,encrypted,_=request('GET','/agent/env/'+id)
 check(status==200 and b'fixture-only' not in encrypted,'HTTP download contains ciphertext only')
 target=RUN/'.env';target.write_bytes(b'EXISTING=fixture-old')
 p=append(url,target,key)
 check(p.returncode==0 and target.read_bytes()==b'EXISTING=fixture-old\n'+fixture.encode(),'short sh preserves existing bytes and appends the exact dotenv')
 check(p.stdout.strip()=='OK' and 'fixture-only' not in p.stdout+p.stderr,'receiver output contains only OK')
 check(target.stat().st_mode&0o777==0o600,'appended dotenv permissions are private')
 local=RUN/'.env.key'; marker=RUN/'must-not-execute'
 existing=('FAMILY_KEYS_K='+key+'\r\nDO_NOT_EXECUTE=$(touch '+str(marker)+')\n').encode()
 local.write_bytes(existing)
 env=dict(os.environ);env.pop('K',None);env.pop('FAMILY_KEYS_K',None)
 p=subprocess.run(['sh',str(ROOT/'append-env.sh'),url,str(local)],env=env,cwd=ROOT,text=True,capture_output=True,timeout=10)
 check(p.returncode==0 and local.read_bytes()==existing+b'\n'+fixture.encode(),'helper automatically uses the key in the destination dotenv and preserves existing content')
 check(not marker.exists() and p.stdout.strip()=='OK','dotenv key loading never executes dotenv content or prints values')
 central=RUN/'key.env';central.write_bytes(keyfile)
 skill_target=RUN/'.env.skill';skill_target.write_bytes(b'EXISTING=fixture-old')
 env['FAMILY_KEYS_KEY_FILE']=str(central)
 helper=RUN/'skill/family-keys/scripts/append-env.sh'
 p=subprocess.run(['sh',str(helper),url,str(skill_target)],env=env,cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode==0 and p.stdout.strip()=='OK' and skill_target.read_bytes()==b'EXISTING=fixture-old\n'+fixture.encode(),'packaged skill receives into a project without a per-project decryption key')
 cli=RUN/'skill/family-keys/scripts/register-env.sh'
 cli_source=RUN/'.env.registration'
 cli_source.write_text('UNRELATED="fixture-unrelated\nCLI_TOKEN=decoy\n"\nexport CLI_TOKEN = "fixture-registered-Ω"\n')
 capture=RUN/'registration-wire.json'
 bin_dir=RUN/'capture-bin';bin_dir.mkdir()
 curl=bin_dir/'curl'
 curl.write_text('#!/bin/sh\ntee "$KEYS_TEST_CAPTURE" | '+shlex.quote(shutil.which('curl'))+' "$@"\n')
 curl.chmod(0o700)
 cli_env=dict(env,KEYS_TEST_CAPTURE=str(capture),PATH=str(bin_dir)+os.pathsep+env['PATH'])
 command=['sh',str(cli),f'http://localhost:{port}',str(cli_source),'CLI_TOKEN','CLI登録','用途は自動化の認証']
 p=subprocess.run(command,env=cli_env,cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode==0 and p.stdout.strip()=='OK' and 'fixture-' not in p.stdout+p.stderr,'packaged CLI registers the named variable without opening a browser or exposing values')
 message=json.loads(capture.read_text())
 check('fixture-' not in capture.read_text() and set(message)=={'title','purpose','variable','nonce','iv','cipher','mac'},'CLI sends ciphertext and searchable metadata only')
 result=rpc('search_env',{'query':'自動化の認証'})['items']
 check(len(result)==1 and result[0]['variables']==['CLI_TOKEN'],'CLI registration is searchable by purpose and keeps only the selected variable')
 encrypted=rpc('prepare_env',{'id':result[0]['id']})['url']
 cli_received=RUN/'.env.registration-result'
 p=append(encrypted,cli_received,key)
 check(p.returncode==0 and cli_received.read_text()=='\nCLI_TOKEN= "fixture-registered-Ω"\n','CLI registration preserves the selected dotenv assignment including quoting')
 check(request('POST','/agent/register',message)[0]==200 and rpc('search_env',{'query':'自動化の認証'})['items']==result,'replaying the same encrypted upload does not create a duplicate')
 check(request('GET','/intake/cli-'+message['nonce']+'/info')[0]==404,'CLI registrations cannot be submitted through the browser intake route')
 tampered=dict(message,variable='DIFFERENT_TOKEN')
 check(request('POST','/agent/register',tampered)[0]==403,'CLI authenticates the upload metadata')
 tampered=dict(message,cipher=('B' if message['cipher'][0]=='A' else 'A')+message['cipher'][1:])
 check(request('POST','/agent/register',tampered)[0]==403,'CLI authenticates the encrypted value before decoding')
 cli_source.write_text('BATCH_ONE=fixture-one\nBATCH_TWO=fixture-two\n')
 batch_cli=['sh',str(cli),f'http://localhost:{port}',str(cli_source),'BATCH_ONE','Batch one','Batch fixture','BATCH_TWO','Batch two','Batch fixture']
 p=subprocess.run(batch_cli,env=cli_env,cwd=RUN,text=True,capture_output=True,timeout=10)
 upload=json.loads(capture.read_text())
 check(p.returncode==0 and p.stdout.strip()=='OK' and len(upload['entries'])==2 and 'fixture-' not in capture.read_text(),'CLI batch uploads multiple encrypted entries in a single request')
 check(request('POST','/agent/register',upload)[0]==200 and len(rpc('search_env',{'queries':['BATCH_ONE','BATCH_TWO']})['items'])==2,'replaying a CLI batch produces no duplicates')
 lookup=rpc('search_env',{'queries':['BATCH_ONE','TEST_PASSWORD']})
 check({v for row in lookup['items'] for v in row['variables']}=={'BATCH_ONE','TEST_PASSWORD'},'MCP searches multiple terms in a single call')
 check(all('has_totp' not in row for row in lookup['items'] if row['variables']==['BATCH_ONE']),'search omits TOTP metadata for items without it')
 batch_url=rpc('prepare_env',{'vars':['BATCH_ONE','TEST_PASSWORD']})['url']
 mode_check='import sys,json,base64; header, env, codes=sys.stdin.read().splitlines(); assert header=="FK1-BATCH" and set(base64.b64decode(env).decode().splitlines())=={"BATCH_ONE=fixture-one","TEST_PASSWORD=fixture-password"}; otp=json.loads(codes); assert set(otp)=={"TEST_PASSWORD"} and otp["TEST_PASSWORD"] in sys.argv[1:]'
 p=subprocess.run(['sh',str(ROOT/'append-env.sh'),batch_url,'-','bundle','python3','-c',mode_check,*expected_codes()],env=dict(os.environ,K=key),cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode==0 and p.stdout.strip()=='OK','single encrypted response delivers selected ENV values and corresponding OTP to a local consumer')
 json_check='import sys,json; data=json.load(sys.stdin); assert set(data)=={"env","totp"}; assert data["env"].endswith("\\n") and set(data["env"].splitlines())=={"BATCH_ONE=fixture-one","TEST_PASSWORD=fixture-password"}; assert set(data["totp"])=={"TEST_PASSWORD"} and data["totp"]["TEST_PASSWORD"] in sys.argv[1:]'
 p=subprocess.run(['sh',str(ROOT/'append-env.sh'),batch_url,'-','bundle-json','python3','-c',json_check,*expected_codes()],env=dict(os.environ,K=key),cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode==0 and p.stdout.strip()=='OK','bundle-json gives the consumer raw dotenv text and TOTP in one JSON object')
 no_otp_url=rpc('prepare_env',{'vars':['BATCH_ONE']})['url']
 no_otp='import json,sys; data=json.load(sys.stdin); sys.exit(10 if data["totp"]=={} else 99)'
 p=subprocess.run(['sh',str(ROOT/'append-env.sh'),no_otp_url,'-','bundle-json','python3','-c',no_otp],env=dict(os.environ,K=key),cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode==10 and p.stdout.strip()=='NO_OTP','bundle-json always includes a totp object, including when no code is present')
 for consumer_status, exit_status, stdout, stderr in [(10,10,'NO_OTP',''),(11,11,'NO_FIELD',''),(12,0,'SUBMITTED',''),(27,1,'','BUNDLE_ERROR')]:
  p=subprocess.run(['sh',str(ROOT/'append-env.sh'),batch_url,'-','bundle-json','sh','-c','cat; printf "fixture-stderr\\n" >&2; exit "$1"','sh',str(consumer_status)],env=dict(os.environ,K=key),cwd=RUN,text=True,capture_output=True,timeout=10)
  check((p.returncode,p.stdout.strip(),p.stderr.strip())==(exit_status,stdout,stderr),f'bundle reports fixed status for exit {consumer_status} and suppresses consumer output')
 batch_file=RUN/'.env.batch'
 p=append(batch_url,batch_file,key)
 check(p.returncode==0 and set(batch_file.read_text().strip().splitlines())=={'BATCH_ONE=fixture-one','TEST_PASSWORD=fixture-password'},'batch dotenv append keeps ephemeral OTPs out of the file')
 change_meta=rpc('manage_env',{'name':'BATCH_ONE','action':'update','title':'Renamed batch fixture','purpose':'Unique manage search'})
 change_url=change_meta['url']
 change_path=urllib.parse.urlparse(change_url).path
 check(request('POST',change_path,{})[0]==403,'an MCP management ticket needs shared key proof')
 cli_source.write_text('BATCH_ONE=fixture-updated\n')
 command_update=['sh',str(cli),'--change',change_url,'BATCH_ONE',str(cli_source)]
 p=subprocess.run(command_update,env=cli_env,cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode==0 and p.stdout.strip()=='OK' and 'fixture-updated' not in capture.read_text(),'MCP updates an existing ENV with encrypted input')
 changed=rpc('search_env',{'query':'Unique manage search'})['items']
 check(len(changed)==1 and changed[0]['name']=='Renamed batch fixture' and changed[0]['variables']==['BATCH_ONE'],'MCP updates searchable metadata on the same ENV')
 updated_file=RUN/'.env.changed'
 check(append(rpc('prepare_env',{'vars':['BATCH_ONE']})['url'],updated_file,key).returncode==0 and updated_file.read_text().strip()=='BATCH_ONE=fixture-updated','unique ENV lookup retrieves the replacement value')
 check(subprocess.run(command_update,env=cli_env,cwd=RUN,capture_output=True,timeout=10).returncode!=0,'successful management tickets cannot be reused')
 stale_url=rpc('manage_env',{'name':'BATCH_ONE','action':'delete'})['url']
 meta_url=rpc('manage_env',{'name':'BATCH_ONE','action':'update','purpose':'Revised manage search'})['url']
 check(subprocess.run(['sh',str(cli),'--change',meta_url,'BATCH_ONE'],env=cli_env,cwd=RUN,capture_output=True,timeout=10).returncode==0,'MCP can update metadata without a source file')
 check(subprocess.run(['sh',str(cli),'--delete',stale_url,'BATCH_ONE'],env=cli_env,cwd=RUN,capture_output=True,timeout=10).returncode!=0,'an outdated ticket cannot delete a newer revision')
 delete_url=rpc('manage_env',{'name':'BATCH_TWO','action':'delete'})['url']
 delete_command=['sh',str(cli),'--delete',delete_url,'BATCH_TWO']
 check(subprocess.run(delete_command[:-1]+['BATCH_ONE'],env=cli_env,cwd=RUN,capture_output=True,timeout=10).returncode!=0,'deletion proof is bound to the requested ENV')
 check(subprocess.run(delete_command,env=cli_env,cwd=RUN,capture_output=True,timeout=10).returncode==0 and 'error' in rpc_response('prepare_env',{'vars':['BATCH_TWO']}),'MCP deletes by ENV name')
 totp_url=rpc('manage_env',{'name':'BATCH_ONE','action':'totp'})['url']
 check('error' in rpc_response('manage_env',{'name':'BATCH_ONE','action':'totp','seed':otp_uri}),'MCP rejects URI fields and accepts only setup metadata')
 totp_file=RUN/'fixture-otpauth'
 totp_file.write_text(otp_uri+'\n')
 setup_totp=['sh',str(cli),'--totp',totp_url,'BATCH_ONE']
 failed=subprocess.run(setup_totp+['-'],env=cli_env,cwd=RUN,input=otp_uri+'&digits=8',text=True,capture_output=True,timeout=10)
 check(failed.returncode!=0 and seed not in failed.stdout+failed.stderr and not rpc('search_env',{'query':'BATCH_ONE'})['items'][0].get('has_totp'),'invalid encrypted URI leaves an item unchanged')
 p=subprocess.run(setup_totp+[str(totp_file)],env=cli_env,cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode==0 and p.stdout.strip()=='OK' and 'otpauth:' not in capture.read_text() and seed not in capture.read_text(),'MCP otpauth setup sends only authenticated ciphertext')
 check(rpc('search_env',{'query':'BATCH_ONE'})['items'][0].get('has_totp') is True,'MCP otpauth setup enables TOTP for the original ENV')
 second_url=rpc('manage_env',{'name':'BATCH_ONE','action':'totp'})['url']
 p=subprocess.run(['sh',str(cli),'--totp',second_url,'BATCH_ONE','-'],env=cli_env,cwd=RUN,input=otp_uri+'\n',text=True,capture_output=True,timeout=10)
 check(p.returncode==0,'encrypted stdin can update an existing otpauth setup')
 totp_bundle=rpc('prepare_env',{'vars':['BATCH_ONE']})['url']
 verify_setup='import json,sys; data=json.load(sys.stdin); assert data["env"]=="BATCH_ONE=fixture-updated\\n"; assert data["totp"]["BATCH_ONE"] in sys.argv[1:]'
 p=subprocess.run(['sh',str(ROOT/'append-env.sh'),totp_bundle,'-','bundle-json','python3','-c',verify_setup,*expected_codes()],env=dict(os.environ,K=key),cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode==0,'MCP otpauth registration yields a valid code and preserves the stored ENV value')
 cli_source.write_text('INITIAL_TOTP=fixture-initial\n')
 initial=['sh',str(cli),'--with-totp',f'http://localhost:{port}',str(cli_source),'INITIAL_TOTP','Initial TOTP fixture','Initial TOTP setup']
 p=subprocess.run(initial+['-'],env=cli_env,cwd=RUN,input=otp_uri+'&period=60',text=True,capture_output=True,timeout=10)
 check(p.returncode!=0 and not rpc('search_env',{'query':'INITIAL_TOTP'})['items'],'invalid initial otpauth rejects the entire CLI registration')
 p=subprocess.run(initial+[str(totp_file)],env=cli_env,cwd=RUN,text=True,capture_output=True,timeout=10)
 initial_upload=json.loads(capture.read_text())
 check(p.returncode==0 and initial_upload.get('cipher') and all(text not in capture.read_text() for text in (seed, 'otpauth:', 'fixture-initial')),'CLI encrypts both initial inputs in one envelope')
 check(request('POST','/agent/register',initial_upload)[0]==200 and rpc('search_env',{'query':'INITIAL_TOTP'})['items'][0].get('has_totp') is True,'initial registration stores TOTP and accepts encrypted retries')
 cli_source.write_text('CLI_TOKEN=fixture-first\nCLI_TOKEN=fixture-second\n')
 p=subprocess.run(command,env=cli_env,cwd=RUN,text=True,capture_output=True,timeout=10)
 check(p.returncode!=0 and 'fixture-' not in p.stdout+p.stderr and rpc('search_env',{'query':'自動化の認証'})['items']==result,'ambiguous dotenv values are rejected locally')
 encrypted=request('GET','/agent/env/'+id)[1]
 before=target.read_bytes();p=append(url,target,'wrong-family-secret')
 check(p.returncode!=0 and target.read_bytes()==before,'wrong secret cannot modify the existing dotenv')
 if Path('/usr/bin/openssl').exists():
  other=RUN/'.env.libressl';p=append(url,other,key,'/usr/bin/openssl')
  check(p.returncode==0 and other.read_bytes()==b'\n'+fixture.encode(),'format works with the macOS system OpenSSL as well')
 # Corrupt a fake ciphertext and check that verification rejects it before any append.
 corrupted=bytearray(encrypted);corrupted[-10]=ord('A') if corrupted[-10]!=ord('A') else ord('B')
 class BadCipher(BaseHTTPRequestHandler):
  def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(corrupted)
  def log_message(self,*_):pass
 bad=HTTPServer(('127.0.0.1',0),BadCipher)
 thread=threading.Thread(target=bad.serve_forever,daemon=True);thread.start()
 p=append('http://127.0.0.1:'+str(bad.server_port),target,key)
 bad.shutdown();thread.join();bad.server_close()
 check(p.returncode!=0 and target.read_bytes()==before,'modified ciphertext is rejected without touching dotenv')
 ticket=rpc('begin_intake',{'title':'入力してOK','purpose':'テスト用途','variable':'PASTE_KEY'})
 missing_env=payload('POST','/mcp',{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'begin_intake','arguments':{'title':'Invalid fixture'}}})[1]
 check(missing_env['error']['code']==-32602,'MCP requires an explicit ENV name for registration')
 check('error' in rpc_response('begin_intake',{'title':'Invalid fixture','variable':'UNREGISTERED','otpauth':otp_uri}),'MCP initial setup only takes metadata')
 group=rpc('begin_intake',{'items':[{'title':'Group A','variable':'GROUP_A'},{'title':'Group B','variable':'GROUP_B'}]})
 group_path=urlsplit(group['url']).path
 _,group_info=payload('GET',group_path+'/info')
 group_auth={'Cookie':'','X-Intake-CSRF':group_info['csrf']}
 check([item['variable'] for item in group_info['items']]==['GROUP_A','GROUP_B'],'one browser form contains all requested ENV inputs')
 check(request('POST',group_path,{'values':['fixture-a','']},group_auth)[0]==400 and rpc('intake_status',{'id':group['id']})=={'status':'waiting'},'an incomplete group does not save any values')
 check(request('POST',group_path,{'values':['fixture-a','fixture-b'],'otpauths':['',otp_uri+'&digits=7']},group_auth)[0]==400 and rpc('intake_status',{'id':group['id']})=={'status':'waiting'},'invalid otpauth leaves the whole group waiting')
 check(request('POST',group_path,{'values':['fixture-a','fixture-b'],'otpauths':['',otp_uri]},group_auth)[0]==200 and len(rpc('wait_intake',{'id':group['id']})['item_ids'])==2,'one submit saves separate ENV items with optional initial TOTP')
 check(rpc('search_env',{'query':'GROUP_B'})['items'][0].get('has_totp') is True and 'has_totp' not in rpc('search_env',{'query':'GROUP_A'})['items'][0],'group TOTP is attached to the matching ENV only')
 tid=ticket['id']
 check(ticket['url'].startswith('http://') and '/intake/' in ticket['url'],'MCP returns a browser input URL on HTTP')
 check(request('GET','/intake/'+tid,headers={'Cookie':''})[0]==200,'human input page works without vault login')
 status,info=payload('GET','/intake/'+tid+'/info',headers={'Cookie':''})
 check(status==200 and info['status']=='waiting','input transaction has a scoped nonce')
 check(payload('POST','/intake/'+tid,{'value':'fixture-pasted'},{'Cookie':'','X-Intake-CSRF':'wrong'})[0]==403,'input submission requires its nonce')
 posted=[]
 def person():posted.append(payload('POST','/intake/'+tid,{'value':'fixture-pasted','otpauth':otp_uri},{'Cookie':'','X-Intake-CSRF':info['csrf']})[0])
 timer=threading.Timer(.2,person);timer.start();receipt=rpc('wait_intake',{'id':tid});timer.join()
 check(rpc('search_env',{'query':'PASTE_KEY'})['items'][0].get('has_totp') is True,'one-time single item form supports TOTP on first save')
 check(posted==[200] and receipt['status']=='ok','human OK completes a direct HTTP MCP wait')
 check(rpc('search_env',{'query':'テスト用途'})=={'items':[{'id':receipt['item_id'],'name':'入力してOK','variables':['PASTE_KEY'],'has_totp':True}]},'a fresh MCP connection finds the registered key by purpose alone')
 check('fixture-pasted' not in json.dumps(receipt) and key not in json.dumps(receipt),'completion contains neither token nor shared secret')
 check(payload('POST','/intake/'+tid,{'value':'fixture-again'},{'Cookie':'','X-Intake-CSRF':info['csrf']})[0]==409,'input transaction cannot be submitted twice')
 delivery=rpc('prepare_env',{'id':receipt['item_id']});out=RUN/'.env.paste';p=append(delivery['url'],out,key)
 check(p.returncode==0 and b'fixture-pasted' in out.read_bytes(),'human-submitted token can be decrypted and appended')
 methods=payload('POST','/mcp',{'jsonrpc':'2.0','id':1,'method':'tools/list'})[1]
 check(key not in json.dumps(methods),'MCP never publishes the family rule')
 for index in range(13):
  status, _=payload('POST','/api/items',{'name':f'Bulk fixture {index}','note':'上限チェック'})
  assert status==200
 limited=rpc('search_env',{'query':'上限チェック'})
 check(len(limited['items'])==12 and limited['more'] is True,'broad MCP search caps output and signals more results')
 check(payload('POST','/api/logout',{})[0]==200,'human can log out')
 check(request('GET','/api/family-rule')[0]==401,'family rule is hidden again after logout')
 server.terminate();stdout,stderr=server.communicate(timeout=5);server=None
 legacy=RUN/'legacy.gd'
 legacy.write_text('''const Core = preload("../../core.gd")
func main(args) -> int:
	var vault := Core.new()
	vault.open(args[0])!
	var row := vault.find(args[1])
	row.id = "legacy-collision"
	row.mac = GD.data.raw_to_base64(vault.signature(row))
	vault.db.exec("INSERT INTO items(id,record) VALUES(?,?)", [row.id, GD.data.var_to_json(row)!])!
	return 0
''')
 fixture_id=changed[0]['id']
 p=subprocess.run([str(GD),str(legacy),str(RUN),fixture_id],cwd=ROOT,capture_output=True,timeout=5)
 check(p.returncode==0,'fixture simulates a signed duplicate from before the unique index')
 server=start()
 with zipfile.ZipFile(io.BytesIO(request('GET','/assets/family-keys-skill.zip')[1])) as bundle:
  check(bundle.read('family-keys/SKILL.md').decode()==distribution_saved['skill'],'edited distribution survives a restart')
 check('error' in rpc_response('prepare_env',{'vars':['BATCH_ONE']}) and 'error' in rpc_response('manage_env',{'name':'BATCH_ONE','action':'delete'}),'legacy collision has no implicit ENV lookup or delete target')
 duplicate_url=rpc('manage_env',{'name':'BATCH_ONE','id':'legacy-collision','action':'delete'})['url']
 check(subprocess.run(['sh',str(cli),'--delete',duplicate_url,'BATCH_ONE'],env=cli_env,cwd=RUN,capture_output=True,timeout=10).returncode==0 and 'url' in rpc('prepare_env',{'vars':['BATCH_ONE']}),'resolving a legacy collision restores exact ENV lookup')
 server.terminate();more_out,more_err=server.communicate(timeout=5);server=None
 stdout+=more_out;stderr+=more_err
 check(b'fixture-' not in stdout+stderr,'server logs contain no fake secret values')
 check('fixture-' not in (RUN/'audit.jsonl').read_text(),'audit log omits value contents')
 with sqlite3.connect(RUN/'keys.sqlite3') as c:
  ident,record=c.execute('SELECT id,record FROM items LIMIT 1').fetchone();row=json.loads(record);row['name']='tampered';c.execute('UPDATE items SET record=? WHERE id=?',(json.dumps(row),ident))
 p=subprocess.run([str(GD),'serve','server.gd',str(RUN)],cwd=ROOT,capture_output=True,timeout=5)
 check(p.returncode!=0,'tampered storage cannot be opened')
 print(f'Completed {checks} checks with generated fixtures only.')
finally:
 if server:server.terminate();server.communicate(timeout=5)
