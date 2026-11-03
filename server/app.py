#!/usr/bin/env python3
"""Standalone, read-only Wazuh SOC console with local triage/case notes."""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import ssl
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import Request, urlopen

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
INDEXER_URL=os.environ.get("INDEXER_URL","https://127.0.0.1:9200").rstrip("/")
INDEXER_CA=os.environ.get("INDEXER_CA","/etc/soc-automation/indexer-root-ca.pem")
MANAGER_CONFIG=os.environ.get("MANAGER_CONFIG","/var/ossec/etc/ossec.conf")
OSSEC_LOG=os.environ.get("OSSEC_LOG","/var/ossec/logs/ossec.log")
DB_PATH=os.environ.get("DB_PATH","/var/lib/soc-automation-dashboard/ops.sqlite3")
PORT=int(os.environ.get("PORT","8081"))
TLS_CONTEXT=ssl.create_default_context(cafile=INDEXER_CA)
_AUTH="Basic "+os.environ["INDEXER_AUTH_B64"]
CACHE={"overview_at":0.0,"overview":None}
CACHE_LOCK=threading.Lock()
TRIAGE_STATES={"New","In progress","Escalated","Closed","False positive"}
CASE_STATES={"Open","Investigating","Contained","Resolved","Closed"}
SERVICES=["wazuh-manager","wazuh-indexer","wazuh-dashboard","filebeat","caddy","soc-automation-dashboard"]

# ---- Login: akun per orang, sesi cookie di memori ----
INDEX_HTML=os.environ.get("INDEX_HTML","/opt/soc-automation-dashboard/index.html")
LOGIN_HTML=os.environ.get("LOGIN_HTML","/opt/soc-automation-dashboard/login.html")
USERS_FILE=os.environ.get("USERS_FILE","/etc/soc-automation/users.json")
COOKIE_PATH=os.environ.get("COOKIE_PATH","/soc-automation/")
ALLOWED_ORIGINS={o.strip() for o in os.environ.get("ALLOWED_ORIGINS","wazuh.toyspedia.fun,127.0.0.1:8081").split(",") if o.strip()}
COOKIE_NAME="soc_session"
SESSION_ABS=12*3600
SESSION_IDLE=2*3600
MAX_FAILS=5
FAIL_WINDOW=900
SESSIONS={}
SESSIONS_LOCK=threading.Lock()
FAILS={}
FAILS_LOCK=threading.Lock()
CSP="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

def hash_password(pw,salt=None,n=2**14,r=8,p=1):
    salt=salt or os.urandom(16)
    dk=hashlib.scrypt(pw.encode(),salt=salt,n=n,r=r,p=p,dklen=32)
    return "scrypt$%d$%d$%d$%s$%s"%(n,r,p,salt.hex(),dk.hex())

def verify_password(pw,stored):
    try:
        _,n,r,p,salt,dk=stored.split("$")
        calc=hashlib.scrypt(pw.encode(),salt=bytes.fromhex(salt),n=int(n),r=int(r),p=int(p),dklen=32)
        return hmac.compare_digest(calc.hex(),dk)
    except Exception:return False

DUMMY_HASH=hash_password("password-pembanding-waktu")

def load_users():
    try:
        with open(USERS_FILE,encoding="utf-8") as f:data=json.load(f)
        return data if isinstance(data,dict) else {}
    except FileNotFoundError:return {}
    except Exception as exc:
        logging.warning("Could not read users file: %s",type(exc).__name__)
        return {}

def new_session(user,role):
    token=secrets.token_urlsafe(32);now=time.time()
    with SESSIONS_LOCK:
        for k in [k for k,v in SESSIONS.items() if now-v["created"]>SESSION_ABS or now-v["seen"]>SESSION_IDLE]:del SESSIONS[k]
        SESSIONS[token]={"user":user,"role":role,"created":now,"seen":now}
    return token

def get_session(token):
    if not token:return None
    now=time.time()
    with SESSIONS_LOCK:
        s=SESSIONS.get(token)
        if not s:return None
        if now-s["created"]>SESSION_ABS or now-s["seen"]>SESSION_IDLE:
            del SESSIONS[token];return None
        s["seen"]=now
        return dict(s)

def too_many_fails(*keys):
    now=time.time()
    with FAILS_LOCK:
        return any(len([t for t in FAILS.get(k,[]) if now-t<FAIL_WINDOW])>=MAX_FAILS for k in keys)

def note_fail(*keys):
    now=time.time()
    with FAILS_LOCK:
        if len(FAILS)>5000:
            for k in [k for k,v in FAILS.items() if not any(now-t<FAIL_WINDOW for t in v)]:del FAILS[k]
        for k in keys:FAILS[k]=[t for t in FAILS.get(k,[]) if now-t<FAIL_WINDOW]+[now]

def clear_fails(*keys):
    with FAILS_LOCK:
        for k in keys:FAILS.pop(k,None)


def db():
    con=sqlite3.connect(DB_PATH,timeout=10)
    con.row_factory=sqlite3.Row
    return con

def init_db():
    os.makedirs(os.path.dirname(DB_PATH),exist_ok=True)
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS triage(alert_id TEXT PRIMARY KEY,status TEXT NOT NULL,assignee TEXT NOT NULL DEFAULT '',note TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cases(case_id TEXT PRIMARY KEY,title TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL,owner TEXT NOT NULL DEFAULT '',summary TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS case_alerts(case_id TEXT NOT NULL,alert_id TEXT NOT NULL,PRIMARY KEY(case_id,alert_id));
        CREATE TABLE IF NOT EXISTS case_timeline(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT NOT NULL,at TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,details TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,details TEXT NOT NULL DEFAULT '');
        """)

def now_iso(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

def es_search(index,body):
    url=INDEXER_URL+"/"+quote(index,safe="-*")+"/_search"
    req=Request(url,data=json.dumps(body).encode(),method="POST")
    req.add_header("Authorization",_AUTH);req.add_header("Content-Type","application/json")
    with urlopen(req,context=TLS_CONTEXT,timeout=12) as resp:return json.loads(resp.read().decode())

def es_get(path):
    req=Request(INDEXER_URL+path,headers={"Authorization":_AUTH})
    with urlopen(req,context=TLS_CONTEXT,timeout=8) as resp:return json.loads(resp.read().decode())

def range_filter(field,after):return {"range":{field:{"gte":after}}}
def level_filter(minimum=3,maximum=None):
    value={"gte":minimum}
    if maximum is not None:value["lt"]=maximum
    return {"range":{"rule.level":value}}
def bool_filters(filters):return {"bool":{"filter":filters}}

def automation_config():
    try:
        with open(MANAGER_CONFIG,encoding="utf-8") as f:text=f.read()
        root=ET.fromstring("<wazuh-config-root>"+text+"</wazuh-config-root>")
        blocks=[node for section in root.findall("ossec_config") for node in section.findall("active-response")]
        enabled=[b for b in blocks if (b.findtext("disabled") or "no").strip().lower() not in ("yes","true","1")]
        return {"configured":bool(enabled),"count":len(enabled)}
    except Exception as exc:
        logging.warning("Could not inspect active-response config: %s",type(exc).__name__)
        return {"configured":None,"count":None}

def severity_name(level):
    if level>=12:return "Critical"
    if level>=8:return "High"
    if level>=4:return "Medium"
    return "Low"

def source_alert(hit):
    s=hit.get("_source",{});r=s.get("rule",{});a=s.get("agent",{});d=s.get("data",{})
    return {"id":hit.get("_id",""),"timestamp":s.get("timestamp",""),"agent":a.get("name","unknown"),"agent_id":a.get("id",""),"rule_id":str(r.get("id","")),"level":int(r.get("level",0)),"severity":severity_name(int(r.get("level",0))),"description":r.get("description",""),"groups":r.get("groups",[]),"mitre":r.get("mitre",{}),"srcip":d.get("srcip",d.get("src_ip","")),"url":d.get("url",""),"hash":d.get("sha256_after",d.get("md5_after","")),"triage":{"status":"New","assignee":"","note":""}}

def get_alert_docs(days=7,limit=300,minimum=3,maximum=None):
    filters=[range_filter("timestamp",f"now-{days}d"),level_filter(minimum,maximum)]
    body={"size":max(1,min(int(limit),500)),"track_total_hits":True,"query":bool_filters(filters),"sort":[{"timestamp":{"order":"desc"}}],"_source":["timestamp","agent.name","agent.id","rule.id","rule.level","rule.description","rule.groups","rule.mitre","data.srcip","data.src_ip","data.url","data.sha256_after","data.md5_after"]}
    res=es_search("wazuh-alerts-*",body)
    docs=[source_alert(h) for h in res.get("hits",{}).get("hits",[])]
    ids=[a["id"] for a in docs if a["id"]]
    if ids:
        with db() as con:
            marks=','.join('?' for _ in ids)
            states={r['alert_id']:dict(r) for r in con.execute(f"SELECT * FROM triage WHERE alert_id IN ({marks})",ids)}
        for a in docs:
            if a['id'] in states:
                s=states[a['id']];a['triage']={"status":s['status'],"assignee":s['assignee'],"note":s['note'],"updated_at":s['updated_at']}
    return docs,int(res.get("hits",{}).get("total",{}).get("value",0))

def top_rules(days=7,minimum=10):
    res=es_search("wazuh-alerts-*",{"size":0,"query":bool_filters([range_filter("timestamp",f"now-{days}d"),level_filter(minimum)]),"aggs":{"rules":{"terms":{"field":"rule.id","size":10,"order":{"_count":"desc"}},"aggs":{"description":{"terms":{"field":"rule.description","size":1}},"max_level":{"max":{"field":"rule.level"}}}}}})
    out=[]
    for b in res.get("aggregations",{}).get("rules",{}).get("buckets",[]):
        ds=b.get("description",{}).get("buckets",[])
        out.append({"id":str(b.get("key","")),"description":ds[0]["key"] if ds else "(description unavailable)","count":int(b.get("doc_count",0)),"level":int(b.get("max_level",{}).get("value") or 0)})
    return out

def overview():
    a24=es_search("wazuh-alerts-*",{"size":0,"query":bool_filters([range_filter("timestamp","now-24h"),level_filter(10)])})
    c24=es_search("wazuh-alerts-*",{"size":0,"query":bool_filters([range_filter("timestamp","now-24h"),level_filter(12)])})
    active=es_search("wazuh-monitoring-*",{"size":0,"query":bool_filters([range_filter("timestamp","now-1h"),{"term":{"status":"active"}}]),"aggs":{"agents":{"cardinality":{"field":"name"}}}})
    active_count=int(active.get("aggregations",{}).get("agents",{}).get("value",0))
    trend_res=es_search("wazuh-alerts-*",{"size":0,"query":bool_filters([range_filter("timestamp","now-14d"),level_filter(3)]),"aggs":{"days":{"date_histogram":{"field":"timestamp","calendar_interval":"day","min_doc_count":0},"aggs":{"levels":{"terms":{"field":"rule.level","size":20}}}}}})
    trend=[]
    for b in trend_res.get("aggregations",{}).get("days",{}).get("buckets",[]):
        row={"date":b.get("key_as_string","")[:10],"critical":0,"high":0,"medium":0,"low":0}
        for level in b.get("levels",{}).get("buckets",[]):row[severity_name(int(level.get("key",0))).lower()]+=int(level.get("doc_count",0))
        trend.append(row)
    sev_res=es_search("wazuh-alerts-*",{"size":0,"query":bool_filters([range_filter("timestamp","now-7d"),level_filter(3)]),"aggs":{"levels":{"terms":{"field":"rule.level","size":20}}}})
    severity={"Critical":0,"High":0,"Medium":0,"Low":0}
    for b in sev_res.get("aggregations",{}).get("levels",{}).get("buckets",[]):severity[severity_name(int(b["key"]))]+=int(b["doc_count"])
    threats=es_search("wazuh-alerts-*",{"size":0,"query":bool_filters([range_filter("timestamp","now-7d"),level_filter(3)]),"aggs":{"threats":{"terms":{"field":"rule.description","size":10}}}})
    mitre=es_search("wazuh-alerts-*",{"size":0,"query":bool_filters([range_filter("timestamp","now-7d"),{"exists":{"field":"rule.mitre.tactic"}}]),"aggs":{"tactics":{"terms":{"field":"rule.mitre.tactic","size":10}}}})
    by_agent=es_search("wazuh-alerts-*",{"size":0,"query":bool_filters([range_filter("timestamp","now-7d"),level_filter(10)]),"aggs":{"agents":{"terms":{"field":"agent.name","size":10}}}})
    recent,_=get_alert_docs(days=1,limit=20,minimum=10)
    return {"generated_at":now_iso(),"metrics":{"candidate_alerts_24h":int(a24["hits"]["total"]["value"]),"critical_alerts_24h":int(c24["hits"]["total"]["value"]),"active_agents_1h":active_count},"trend":trend,"severity":severity,"top_rules":top_rules(7,10),"top_threats":[{"name":b["key"],"count":int(b["doc_count"])} for b in threats.get("aggregations",{}).get("threats",{}).get("buckets",[])],"mitre":[{"name":b["key"],"count":int(b["doc_count"])} for b in mitre.get("aggregations",{}).get("tactics",{}).get("buckets",[])],"by_agent":[{"name":b["key"],"count":int(b["doc_count"])} for b in by_agent.get("aggregations",{}).get("agents",{}).get("buckets",[])],"recent_candidates":recent,"automation":{"active_response":automation_config()}}

def health_data():
    names=["wazuh-manager","wazuh-indexer","wazuh-dashboard","filebeat","caddy","soc-automation-dashboard"]
    services={}
    for name in names:
        try:
            p=subprocess.run(["systemctl","is-active",name],capture_output=True,text=True,timeout=3)
            services[name]=p.stdout.strip() or "unknown"
        except Exception:services[name]="unknown"
    try:cluster=es_get("/_cluster/health?filter_path=status,number_of_nodes,active_shards,unassigned_shards")
    except Exception as exc:cluster={"status":"unknown","error":type(exc).__name__}
    eps15=int(es_search("wazuh-alerts-*",{"size":0,"query":{"range":{"timestamp":{"gte":"now-15m"}}}}).get("hits",{}).get("total",{}).get("value",0))
    latest=es_search("wazuh-alerts-*",{"size":0,"aggs":{"last":{"max":{"field":"timestamp"}}}}).get("aggregations",{}).get("last",{}).get("value_as_string")
    agents=es_search("wazuh-monitoring-*",{"size":100,"sort":[{"timestamp":{"order":"desc"}}],"_source":["name","id","status","ip","os","version","timestamp"]})
    seen=set();agent_rows=[]
    for hit in agents.get("hits",{}).get("hits",[]):
        s=hit.get("_source",{});key=str(s.get("id") or s.get("name"))
        if key in seen:continue
        seen.add(key);agent_rows.append({"name":s.get("name","unknown"),"id":s.get("id",""),"status":s.get("status","unknown"),"ip":s.get("ip",""),"os":s.get("os",""),"version":s.get("version",""),"timestamp":s.get("timestamp","")})
    errors=[]
    try:
        with open(OSSEC_LOG,encoding="utf-8",errors="replace") as f:lines=f.readlines()[-1200:]
        errors=[line.strip()[:400] for line in lines if re.search(r'\b(error|failed|warning)\b',line,re.I)][-20:]
    except Exception:pass
    return {"generated_at":now_iso(),"services":services,"cluster":cluster,"alerts_15m":eps15,"latest_alert":latest,"agents":agent_rows,"pipeline_warnings":errors}

def get_ioc(value):
    value=value.strip()[:250]
    if not value:raise ValueError("Masukkan IP, domain, URL, atau hash")
    should=[{"term":{"data.srcip":value}},{"term":{"data.url":value}},{"term":{"data.sha256_after":value}},{"term":{"data.md5_after":value}},{"match_phrase":{"full_log":value}}]
    body={"size":50,"track_total_hits":True,"query":{"bool":{"filter":[range_filter("timestamp","now-30d")],"should":should,"minimum_should_match":1}},"sort":[{"timestamp":{"order":"desc"}}],"_source":["timestamp","agent.name","rule.id","rule.level","rule.description","data.srcip","data.url","data.sha256_after","data.md5_after"]}
    res=es_search("wazuh-alerts-*",body)
    return {"value":value,"observed":int(res.get("hits",{}).get("total",{}).get("value",0)),"reputation":"Not checked — no external TI provider connected","events":[source_alert(h) for h in res.get("hits",{}).get("hits",[])]}

def investigate(alert_id):
    req=es_search("wazuh-alerts-*",{"size":1,"query":{"ids":{"values":[alert_id]}},"_source":True})
    hits=req.get("hits",{}).get("hits",[])
    if not hits:raise KeyError("Alert tidak ditemukan di Wazuh")
    current=source_alert(hits[0]); should=[]
    if current.get("agent_id"):should.append({"term":{"agent.id":current['agent_id']}})
    if current.get("srcip"):should.append({"term":{"data.srcip":current['srcip']}})
    corr=[]
    if should:
        res=es_search("wazuh-alerts-*",{"size":30,"query":{"bool":{"filter":[range_filter("timestamp","now-24h")],"should":should,"minimum_should_match":1}},"sort":[{"timestamp":{"order":"desc"}}],"_source":["timestamp","agent.name","agent.id","rule.id","rule.level","rule.description","data.srcip","data.url"]})
        corr=[source_alert(h) for h in res.get("hits",{}).get("hits",[])]
    score=min(100,current['level']*6+min(20,max(0,len(corr)-1)*3)+(8 if current.get('mitre',{}).get('id') else 0))
    current['risk_score']=score
    current['analysis_mode']='Heuristic correlation; no LLM configured'
    current['summary']=f"Rule {current['rule_id']} ({current['description']}) fired on {current['agent']}; risk score {score}/100. This is a deterministic triage aid, not an AI verdict."
    return {"alert":current,"correlated":corr,"summary":current['summary'],"risk_score":score,"analysis_mode":current['analysis_mode']}

def init_db():
    os.makedirs(os.path.dirname(DB_PATH),exist_ok=True)
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS triage(alert_id TEXT PRIMARY KEY,status TEXT NOT NULL,assignee TEXT NOT NULL DEFAULT '',note TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cases(case_id TEXT PRIMARY KEY,title TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL,owner TEXT NOT NULL DEFAULT '',summary TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS case_alerts(case_id TEXT NOT NULL,alert_id TEXT NOT NULL,PRIMARY KEY(case_id,alert_id));
        CREATE TABLE IF NOT EXISTS case_timeline(id INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT NOT NULL,at TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,details TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,details TEXT NOT NULL DEFAULT '');
        """)

def audit(action,target,details='',actor='system'):
    try:
        with db() as con:con.execute("INSERT INTO audit(at,actor,action,target,details) VALUES(?,?,?,?,?)",(now_iso(),actor,action,target,details[:1000]))
    except Exception as exc:logging.warning("audit write failed: %s",type(exc).__name__)

def db_cases():
    with db() as con:
        rows=con.execute("SELECT c.*,COUNT(ca.alert_id) AS alert_count FROM cases c LEFT JOIN case_alerts ca ON c.case_id=ca.case_id GROUP BY c.case_id ORDER BY c.updated_at DESC LIMIT 200").fetchall()
        return [dict(r) for r in rows]

def db_case(case_id):
    with db() as con:
        row=con.execute("SELECT * FROM cases WHERE case_id=?",(case_id,)).fetchone()
        if not row:return None
        out=dict(row)
        out['timeline']=[dict(r) for r in con.execute("SELECT at,actor,action,details FROM case_timeline WHERE case_id=? ORDER BY id",(case_id,)).fetchall()]
        out['alert_ids']=[r['alert_id'] for r in con.execute("SELECT alert_id FROM case_alerts WHERE case_id=?",(case_id,)).fetchall()]
        return out

def json_response(handler,status,obj,extra=None):
    body=json.dumps(obj,separators=(",",":"),ensure_ascii=False).encode()
    handler.send_response(status)
    for k,v in (extra or []):handler.send_header(k,v)
    handler.send_header("Content-Type","application/json; charset=utf-8");handler.send_header("Content-Length",str(len(body)));handler.send_header("Cache-Control","no-store");handler.send_header("X-Content-Type-Options","nosniff");handler.end_headers();handler.wfile.write(body)

class Handler(BaseHTTPRequestHandler):
    server_version="SOC-Automation-Web/1.0"
    def log_message(self,fmt,*args):logging.info("%s - %s",self.address_string(),fmt%args)
    def client_ip(self):
        fwd=self.headers.get("X-Forwarded-For","")
        return (fwd.split(",")[-1].strip() if fwd else self.client_address[0])[:64]
    def cookie_token(self):
        for part in self.headers.get("Cookie","").split(";"):
            k,_,v=part.strip().partition("=")
            if k==COOKIE_NAME:return v
        return ""
    def session(self):return get_session(self.cookie_token())
    def cookie_header(self,token,max_age):
        attrs=[f"{COOKIE_NAME}={token}",f"Path={COOKIE_PATH}","HttpOnly","SameSite=Lax",f"Max-Age={max_age}"]
        if self.headers.get("X-Forwarded-Proto")=="https":attrs.append("Secure")
        return "; ".join(attrs)
    def send_page(self,path):
        try:
            with open(path,"rb") as f:body=f.read()
        except Exception:self.send_error(500);return
        self.send_response(200)
        for k,v in (("Content-Type","text/html; charset=utf-8"),("Content-Length",str(len(body))),("Cache-Control","no-store"),("X-Content-Type-Options","nosniff"),("X-Frame-Options","DENY"),("Referrer-Policy","no-referrer"),("Content-Security-Policy",CSP)):self.send_header(k,v)
        self.end_headers();self.wfile.write(body)
    def do_login(self,body):
        ip=self.client_ip();name=str(body.get("username","")).strip().lower()[:64];pw=str(body.get("password",""))[:256]
        kip,ku="ip:"+ip,"user:"+name
        if too_many_fails(kip,ku):json_response(self,429,{"error":"Terlalu banyak percobaan. Coba lagi dalam 15 menit."});return
        u=load_users().get(name)
        known=isinstance(u,dict) and "hash" in u
        ok=verify_password(pw,u["hash"] if known else DUMMY_HASH) and known
        if not ok:
            note_fail(kip,ku);audit("login gagal",name or "-",ip,actor=name or "anonim");time.sleep(0.4)
            json_response(self,401,{"error":"Nama pengguna atau kata sandi salah."});return
        clear_fails(ku)
        role=u.get("role","viewer");token=new_session(name,role)
        audit("login",name,ip,actor=name)
        json_response(self,200,{"ok":True,"user":name,"role":role},[("Set-Cookie",self.cookie_header(token,SESSION_ABS))])
    def read_body(self):
        n=int(self.headers.get("Content-Length","0"))
        if n<0 or n>20000:raise ValueError("Request body too large")
        return json.loads(self.rfile.read(n).decode() or "{}")
    def do_GET(self):
        u=urlsplit(self.path);path=u.path;qs=parse_qs(u.query)
        if path in ("/","/index.html"):
            self.send_page(INDEX_HTML if self.session() else LOGIN_HTML);return
        if path=="/healthz":json_response(self,200,{"status":"ok"});return
        sess=self.session()
        if path=="/api/me":
            if sess:json_response(self,200,{"user":sess["user"],"role":sess["role"]})
            else:json_response(self,401,{"error":"Login diperlukan"})
            return
        if path.startswith("/api/") and not sess:json_response(self,401,{"error":"Login diperlukan"});return
        if path=="/api/overview":
            try:
                with CACHE_LOCK:
                    if CACHE["overview"] is None or time.monotonic()-CACHE["overview_at"]>15:CACHE["overview"]=overview();CACHE["overview_at"]=time.monotonic()
                    out=CACHE["overview"]
                json_response(self,200,out)
            except Exception as exc:logging.exception("overview failed: %s",type(exc).__name__);json_response(self,503,{"error":"Wazuh data unavailable; check dashboard service logs."})
            return
        if path=="/api/alerts":
            try:
                days=max(1,min(int(qs.get('days',['7'])[0]),30));limit=max(1,min(int(qs.get('limit',['300'])[0]),500))
                minimum=max(3,min(int(qs.get('min_level',['3'])[0]),15));maximum=qs.get('max_level',[None])[0]
                docs,total=get_alert_docs(days,limit,minimum,int(maximum) if maximum else None)
                json_response(self,200,{"total":total,"alerts":docs})
            except Exception as exc:logging.exception("alerts failed: %s",type(exc).__name__);json_response(self,503,{"error":"Alert query unavailable"})
            return
        if path=="/api/investigate":
            try:json_response(self,200,investigate(qs.get('alert_id',[''])[0]))
            except KeyError as exc:json_response(self,404,{"error":str(exc)})
            except Exception as exc:logging.exception("investigation failed: %s",type(exc).__name__);json_response(self,503,{"error":"Investigation query unavailable"})
            return
        if path=="/api/ioc":
            try:json_response(self,200,get_ioc(qs.get('value',[''])[0]))
            except ValueError as exc:json_response(self,400,{"error":str(exc)})
            except Exception as exc:logging.exception("IOC lookup failed: %s",type(exc).__name__);json_response(self,503,{"error":"IOC lookup unavailable"})
            return
        if path=="/api/cases":json_response(self,200,{"cases":db_cases()});return
        if path.startswith("/api/cases/"):
            case_id=path.rsplit('/',1)[-1];case=db_case(case_id)
            if case:json_response(self,200,case)
            else:json_response(self,404,{"error":"Case not found"})
            return
        if path=="/api/health":
            try:json_response(self,200,health_data())
            except Exception as exc:logging.exception("health failed: %s",type(exc).__name__);json_response(self,503,{"error":"Health query unavailable"})
            return
        if path=="/api/admin":
            try:
                with db() as con:logs=[dict(r) for r in con.execute("SELECT at,actor,action,target,details FROM audit ORDER BY id DESC LIMIT 100").fetchall()]
                json_response(self,200,{"source":"Wazuh Indexer read-only (kibanaserver)","manager_config":MANAGER_CONFIG,"indexer_url":"https://127.0.0.1:9200 (loopback)","web_auth":"Login aplikasi (sesi cookie; kata sandi di-hash scrypt)","external_integrations":"Not configured in this app","users":([{"name":n,"role":(u.get("role","viewer") if isinstance(u,dict) else "viewer")} for n,u in sorted(load_users().items())] if sess["role"]=="admin" else []),"audit":logs})
            except Exception as exc:json_response(self,500,{"error":"Could not load admin information"})
            return
        self.send_error(404)
    def do_POST(self):
        origin=self.headers.get('Origin')
        if not origin or urlsplit(origin).netloc not in ALLOWED_ORIGINS:
            json_response(self,403,{"error":"Cross-origin request refused"});return
        try:body=self.read_body()
        except Exception as exc:json_response(self,400,{"error":"Invalid request body"});return
        path=urlsplit(self.path).path
        if path=="/api/login":self.do_login(body);return
        sess=self.session()
        if path=="/api/logout":
            with SESSIONS_LOCK:SESSIONS.pop(self.cookie_token(),None)
            if sess:audit("logout",sess["user"],self.client_ip(),actor=sess["user"])
            json_response(self,200,{"ok":True},[("Set-Cookie",self.cookie_header("",0))]);return
        if not sess:json_response(self,401,{"error":"Login diperlukan"});return
        if sess["role"] not in ("analyst","admin"):json_response(self,403,{"error":"Peran Anda hanya boleh membaca"});return
        if path=="/api/triage":
            alert_id=str(body.get('alert_id',''))[:512];status=str(body.get('status','New'));assignee=str(body.get('assignee',''))[:120].strip();note=str(body.get('note',''))[:2000]
            if not alert_id or status not in TRIAGE_STATES:json_response(self,400,{"error":"Alert ID/status invalid"});return
            try:
                # Ensure the key refers to a real indexed alert, without writing back into Wazuh.
                check=es_search('wazuh-alerts-*',{"size":1,"query":{"ids":{"values":[alert_id]}}})
                if not check.get('hits',{}).get('hits'):json_response(self,404,{"error":"Wazuh alert not found"});return
                with db() as con:con.execute("INSERT INTO triage(alert_id,status,assignee,note,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status,assignee=excluded.assignee,note=excluded.note,updated_at=excluded.updated_at",(alert_id,status,assignee,note,now_iso()))
                audit('triage update',alert_id,f'{status}; assignee={assignee}',sess['user'])
                json_response(self,200,{"ok":True,"stored":"local dashboard state; Wazuh alert is unchanged"})
            except Exception as exc:logging.exception("triage update failed: %s",type(exc).__name__);json_response(self,503,{"error":"Could not save triage state"})
            return
        if path=="/api/cases":
            title=str(body.get('title','')).strip()[:240];ids=[str(v)[:512] for v in body.get('alert_ids',[])[:50] if v]
            owner=str(body.get('owner','')).strip()[:120]
            if not title or not ids:json_response(self,400,{"error":"Title and at least one Wazuh alert are required"});return
            try:
                res=es_search('wazuh-alerts-*',{"size":50,"query":{"ids":{"values":ids}},"_source":["timestamp","agent.name","rule.id","rule.level","rule.description"]})
                hits=res.get('hits',{}).get('hits',[])
                if not hits:json_response(self,404,{"error":"Selected Wazuh alerts were not found"});return
                levels=[int(h.get('_source',{}).get('rule',{}).get('level',0)) for h in hits];sev=severity_name(max(levels or [0]));case_id='CASE-'+datetime.now(timezone.utc).strftime('%Y%m%d')+'-'+secrets.token_hex(2).upper();now=now_iso();summary=f'Local case created from {len(hits)} Wazuh alert(s); Wazuh alerts remain unchanged.'
                with db() as con:
                    con.execute("INSERT INTO cases(case_id,title,severity,status,owner,summary,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",(case_id,title,sev,'Open',owner,summary,now,now))
                    for h in hits:
                        aid=h.get('_id')
                        if aid:con.execute("INSERT OR IGNORE INTO case_alerts(case_id,alert_id) VALUES(?,?)",(case_id,aid))
                    con.execute("INSERT INTO case_timeline(case_id,at,actor,action,details) VALUES(?,?,?,?,?)",(case_id,now,sess['user'],'Case created',summary))
                audit('case created',case_id,summary,sess['user']);json_response(self,201,{"ok":True,"case_id":case_id})
            except Exception as exc:logging.exception("case creation failed: %s",type(exc).__name__);json_response(self,503,{"error":"Could not create local case"})
            return
        if path.startswith('/api/cases/') and path.endswith('/timeline'):
            case_id=path.split('/')[-2];action=str(body.get('action','Note')).strip()[:120];details=str(body.get('details','')).strip()[:2000]
            if not details:json_response(self,400,{"error":"Timeline detail required"});return
            try:
                with db() as con:
                    exists=con.execute("SELECT 1 FROM cases WHERE case_id=?",(case_id,)).fetchone()
                    if not exists:json_response(self,404,{"error":"Case not found"});return
                    now=now_iso();con.execute("INSERT INTO case_timeline(case_id,at,actor,action,details) VALUES(?,?,?,?,?)",(case_id,now,sess['user'],action,details));con.execute("UPDATE cases SET updated_at=? WHERE case_id=?",(now,case_id))
                audit('case timeline',case_id,action+': '+details,sess['user']);json_response(self,200,{"ok":True})
            except Exception as exc:logging.exception("timeline update failed: %s",type(exc).__name__);json_response(self,503,{"error":"Could not update case"})
            return
        if path.startswith('/api/cases/'):
            case_id=path.rsplit('/',1)[-1];status=str(body.get('status','')).strip();owner=str(body.get('owner','')).strip()[:120]
            if status not in CASE_STATES:json_response(self,400,{"error":"Invalid case status"});return
            with db() as con:
                cur=con.execute("UPDATE cases SET status=?,owner=?,updated_at=? WHERE case_id=?",(status,owner,now_iso(),case_id))
                if cur.rowcount==0:json_response(self,404,{"error":"Case not found"});return
            audit('case update',case_id,f'{status}; owner={owner}',sess['user']);json_response(self,200,{"ok":True});return
        self.send_error(404)

if __name__=='__main__':
    init_db()
    logging.info('Starting standalone SOC console at 127.0.0.1:%s',PORT)
    ThreadingHTTPServer(('127.0.0.1',PORT),Handler).serve_forever()
