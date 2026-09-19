#!/usr/bin/env python3
import argparse, base64, ipaddress, os, sys, time
from pathlib import Path
from urllib.parse import urlparse
import pandas as pd
import requests

VT_BASE='https://www.virustotal.com/api/v3'

def classify_ioc(value):
    value=str(value).strip()
    if not value: return 'Unknown'
    try: ipaddress.ip_address(value); return 'IP'
    except ValueError: pass
    if value.lower().startswith(('http://','https://')): return 'URL'
    try:
        host=urlparse('https://'+value).hostname or ''
        if '.' in host and ' ' not in host: return 'Domain'
    except Exception: pass
    return 'Unknown'

def url_id(url): return base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')

def endpoint_for(ioc, typ):
    if typ=='IP': return f'{VT_BASE}/ip/{ioc}'
    if typ=='Domain': return f'{VT_BASE}/domains/{urlparse("https://"+ioc).hostname or ioc}'
    if typ=='URL': return f'{VT_BASE}/urls/{url_id(ioc)}'
    return None

def stats(payload):
    s=payload.get('data',{}).get('attributes',{}).get('last_analysis_stats',{}) or {}
    return {k:int(s.get(k,0) or 0) for k in ('malicious','suspicious','harmless','undetected','timeout')}

def risk(s):
    if s['malicious']>=5: return 'Critical'
    if s['malicious']>=1 or s['suspicious']>=2: return 'High'
    if s['suspicious']>=1: return 'Medium'
    if s['harmless']>0 and s['undetected']>0: return 'Low'
    if sum(s.values())==0: return 'Unknown'
    return 'Low'

def query_vt(ioc, typ, key, timeout=30):
    endpoint=endpoint_for(ioc,typ)
    if not endpoint: return {'Status':'Unknown IOC type','Risk Level':'Unknown'}
    try: r=requests.get(endpoint,headers={'accept':'application/json','x-apikey':key},timeout=timeout)
    except requests.RequestException as e: return {'Status':f'Request error: {e}','Risk Level':'Unknown'}
    if r.status_code==200:
        s=stats(r.json()); return {**{k.title():v for k,v in s.items()},'Risk Level':risk(s),'Status':'Analyzed'}
    if r.status_code==404: return {'Status':'Not found in VirusTotal','Risk Level':'Unknown'}
    if r.status_code==401: return {'Status':'Invalid or missing VirusTotal API key','Risk Level':'Unknown'}
    if r.status_code==429: return {'Status':'VirusTotal rate limit reached','Risk Level':'Unknown'}
    try: detail=r.json().get('error',{}).get('message',r.text[:200])
    except Exception: detail=r.text[:200]
    return {'Status':f'HTTP {r.status_code}: {detail}','Risk Level':'Unknown'}

def main():
    p=argparse.ArgumentParser(description='Check IPs, domains and URLs with VirusTotal.')
    p.add_argument('-i','--input'); p.add_argument('-o','--output',default='reports/ioc_virustotal_report.xlsx')
    p.add_argument('--ioc'); p.add_argument('--dry-run',action='store_true'); p.add_argument('--delay',type=float,default=.25)
    a=p.parse_args()
    if a.ioc: items=pd.DataFrame([{'IOC':a.ioc}]); col='IOC'
    elif a.input:
        path=Path(a.input)
        if not path.exists(): print(f'[ERROR] Input file not found: {path}'); sys.exit(1)
        items=pd.read_excel(path); col=next((c for c in ('IOC','IP_Address','IP','Domain','URL') if c in items.columns),None)
        if not col: print('[ERROR] No IOC column found.'); sys.exit(1)
    else: p.error('Provide --input or --ioc.')
    key=os.getenv('VT_API_KEY','').strip()
    if not a.dry_run and not key:
        print('[ERROR] VT_API_KEY is not set.'); print("PowerShell: $env:VT_API_KEY='YOUR_API_KEY'"); print("Bash: export VT_API_KEY='YOUR_API_KEY'"); sys.exit(1)
    out=[]
    for n,(_,row) in enumerate(items.iterrows(),1):
        ioc=str(row.get(col,'')).strip(); typ=classify_ioc(ioc)
        result={'Record':n,'IOC':ioc,'IOC Type':typ,'Source Status':str(row.get('Status',''))}
        if a.dry_run:
            result.update({'Malicious':'','Suspicious':'','Harmless':'','Undetected':'','Timeout':'','Risk Level':str(row.get('Risk_Level','Not queried')),'Status':'Dry-run / Not queried'})
        elif typ=='Unknown': result.update({'Risk Level':'Unknown','Status':'Invalid or unsupported IOC'})
        else: result.update(query_vt(ioc,typ,key)); time.sleep(max(a.delay,0))
        out.append(result); print(f'[{n}/{len(items)}] {ioc} -> {typ} -> {result.get("Risk Level","Unknown")}')
    Path(a.output).parent.mkdir(parents=True,exist_ok=True); pd.DataFrame(out).to_excel(a.output,index=False); print(f'\n[+] Report created: {a.output}')
if __name__=='__main__': main()
