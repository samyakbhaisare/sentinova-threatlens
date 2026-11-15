"""Start native app processes against Compose data services; logs and PIDs stay local."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
artifacts=ROOT/'artifacts'
artifacts.mkdir(exist_ok=True)
processes=json.loads((artifacts/'processes.json').read_text()) if (artifacts/'processes.json').exists() else {}
commands={
    'api':([sys.executable,'scripts/manage.py','api'],ROOT),
    'worker':([sys.executable,'scripts/manage.py','worker','-Q','ingestion,operations,celery','-n','ingestion@%h'],ROOT),
    'dispatcher':([sys.executable,'scripts/manage.py','worker','-Q','maintenance','-n','maintenance@%h'],ROOT),
    'scheduler':([sys.executable,'scripts/manage.py','scheduler'],ROOT),
    'frontend':(['cmd','/c','npm.cmd','start'] if os.name=='nt' else ['npm','start'],ROOT/'frontend'),
}
for name,(command,cwd) in commands.items():
    if len(sys.argv)>1 and name not in sys.argv[1:]:
        continue
    with (artifacts/(name+'.log')).open('ab') as log:
        process=subprocess.Popen(command,cwd=cwd,stdout=log,stderr=log,stdin=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name=='nt' else 0,
            start_new_session=os.name!='nt')
        processes[name]=process.pid
(artifacts/'processes.json').write_text(json.dumps(processes,indent=2))
print(json.dumps(processes))
