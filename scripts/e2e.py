"""Run browser flows against an isolated real test database; no mocked business APIs."""
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT=Path(__file__).resolve().parents[1]
load_dotenv(ROOT/'.env')
sys.path.insert(0,str(ROOT/'backend'))
os.environ['DATABASE_URL']=os.environ['DATABASE_URL'].replace('localhost','127.0.0.1').rsplit('/',1)[0]+'/threatlens_test'
os.environ['REDIS_URL']='redis://127.0.0.1:6380/2'
os.environ['SEARCH_URL']='http://127.0.0.1:9201'
os.environ['SEARCH_INDEX']='threatlens_test'
os.environ['TEST_MODE']='true'
os.environ['E2E_API_URL']='http://127.0.0.1:8102'
os.environ['E2E_EMAIL']='controlled-browser-'+secrets.token_hex(4)+'@example.org'
os.environ['E2E_PASSWORD']=secrets.token_urlsafe(32)
os.environ['E2E_EMPTY_EMAIL']='controlled-empty-'+secrets.token_hex(4)+'@example.org'
os.environ['E2E_EMPTY_PASSWORD']=secrets.token_urlsafe(32)
from app.db import Session
from app.models import Alert,AlertRule,Feed,Notification,User
from app.intelligence import ingest
from app.security import hasher
from sqlalchemy import delete, select

with Session.begin() as db:
    user=User(name='Controlled browser analyst',email=os.environ['E2E_EMAIL'],password_hash=hasher.hash(os.environ['E2E_PASSWORD']),role='soc_analyst')
    db.add(user);db.flush();identifier=user.id
    empty=User(name='Controlled empty analyst',email=os.environ['E2E_EMPTY_EMAIL'],password_hash=hasher.hash(os.environ['E2E_EMPTY_PASSWORD']),role='soc_analyst')
    db.add(empty);db.flush();empty_identifier=empty.id
    feed=Feed(name='CONTROLLED BROWSER '+secrets.token_hex(4),adapter='json',url='internal',reliability=100,enabled=False,ttl_days=30)
    db.add(feed);db.flush()
    ioc=ingest(db,feed,{'type':'domain','value':'controlled-browser.example.org','confidence':100})
    rule=AlertRule(name='Controlled browser rule',min_score=70,recipient_id=user.id)
    db.add(rule);db.flush()
    db.add(Alert(indicator_id=ioc.id,rule_id=rule.id,score=ioc.score,recipient_id=user.id))
with (ROOT/'artifacts/e2e-api.log').open('ab') as log:
    server=subprocess.Popen([sys.executable,'-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8102'],cwd=ROOT/'backend',stdout=log,stderr=log)
    try:
        for _ in range(40):
            try:
                if httpx.get(os.environ['E2E_API_URL']+'/health/live').status_code==200:break
            except httpx.HTTPError:
                time.sleep(.25)
        command=['cmd','/c','npm.cmd','run','test:e2e'] if os.name=='nt' else ['npm','run','test:e2e']
        result=subprocess.call(command,cwd=ROOT/'frontend',env=os.environ.copy())
    finally:
        server.terminate();server.wait(timeout=10)
        with Session.begin() as db:
            user=db.get(User,identifier);user.enabled=False;user.token_version+=1
            empty=db.get(User,empty_identifier);empty.enabled=False;empty.token_version+=1
            # Remove synthetic browser rules and routed alerts so repeated runs cannot
            # influence other suites. Append-only audit/timeline evidence is retained.
            rules=[r.id for r in db.scalars(select(AlertRule).where(AlertRule.name=='Controlled browser rule')).all()]
            if rules:
                alert_ids=[a.id for a in db.scalars(select(Alert).where(Alert.rule_id.in_(rules))).all()]
                if alert_ids:
                    db.execute(delete(Notification).where(Notification.alert_id.in_(alert_ids)))
                    db.execute(delete(Alert).where(Alert.id.in_(alert_ids)))
                db.execute(delete(AlertRule).where(AlertRule.id.in_(rules)))
raise SystemExit(result)
