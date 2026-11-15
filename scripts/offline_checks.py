"""Docker-free regression runner. Uses installed browser and project-local temporary storage."""
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[1]
temp=ROOT/'artifacts/tmp'
temp.mkdir(parents=True,exist_ok=True)
run=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
env={**os.environ,'TEMP':str(temp),'TMP':str(temp),'TMPDIR':str(temp),'NEXT_TELEMETRY_DISABLED':'1','VERIFICATION_RUN':run}
commands=[
    ('unit',[sys.executable,'-m','pytest','backend/tests','-m','not integration','-q'],ROOT),
    ('security',[sys.executable,'-m','bandit','-r','backend/app','-ll'],ROOT),
    ('typecheck',['cmd','/c','npm.cmd','run','typecheck'] if os.name=='nt' else ['npm','run','typecheck'],ROOT/'frontend'),
]
if os.name=='nt':
    chrome=Path('C:/Program Files/Google/Chrome/Application/chrome.exe')
    if chrome.exists():
        env['E2E_BROWSER_PATH']=str(chrome)
        commands.append(('browser',['cmd','/c','npx.cmd','playwright','test','--config=playwright.offline.config.ts'],ROOT/'frontend'))
failed=False
for name,command,cwd in commands:
    result=subprocess.run(command,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors='replace',timeout=120)
    (ROOT/'artifacts'/('offline-'+run+'-'+name+'.log')).write_text(result.stdout,encoding='utf-8')
    print(result.stdout)
    failed=failed or result.returncode!=0
raise SystemExit(1 if failed else 0)
