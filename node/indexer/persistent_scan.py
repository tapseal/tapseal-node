"""Persistent incremental mempool inspection; no changes to token validity rules."""
import json,time
from decimal import Decimal
import tapseal as T
from persistent_rpc import RpcLimit

SCHEMA='''create table if not exists mempool_scan_cache(
 txid text primary key, first_seen integer not null, checked_at integer,
 next_retry integer not null default 0, failures integer not null default 0,
 is_tapseal integer not null default 0, raw_json text);
 create index if not exists mempool_scan_queue on mempool_scan_cache(checked_at,next_retry,first_seen);'''

def initialize_scan(store,enabled,interval=60,max_seconds=10,max_rpc=100,budget=150):
    store.db.executescript(SCHEMA)
    existing={k:json.loads(v) for k,v in store.db.execute('select key,value from node')}
    previous=existing.get('scanner') or {}
    settings={'version':2,'enabled':bool(enabled),'interval_seconds':interval,'time_budget_seconds':max_seconds,'rpc_budget':max_rpc,'tx_budget':budget,'persistent':True}
    status='starting' if enabled else 'disabled'
    store.put_node(mempool_enabled=bool(enabled),scanner={**previous,**settings,'status':status,'last_progress_at':int(time.time())})

def jsonable(x):
    if isinstance(x,bytes):return x.hex()
    if isinstance(x,int) and not isinstance(x,bool) and abs(x)>2**53:return str(x)
    if isinstance(x,dict):return {k:jsonable(v) for k,v in x.items()}
    if isinstance(x,(list,tuple)):return [jsonable(v) for v in x]
    return x

def candidate(raw,state):
    payload=None
    for output in raw.get('vout',[]):
        payload=T.payload_from_script(bytes.fromhex(output['scriptPubKey']['hex']))
        if payload is not None:break
    if payload is None:return None
    op=err=None
    try:op=jsonable(T.decode(payload))
    except T.DecodeError as exc:err=str(exc)
    tick=op.get('tick') if op else None
    if op and op['op']=='transfer':tick=op['ticks'][0]['tick']
    paid=None
    if op and op['op']=='mint' and state is not None and tick in state.tokens and state.tokens[tick].treasury_spk:
        script=state.tokens[tick].treasury_spk.hex()
        paid=sum(int(Decimal(str(o['value']))*100000000) for i,o in enumerate(raw['vout']) if i!=op['vout'] and o['scriptPubKey']['hex']==script)
    return {'kind':op['op'] if op else 'cenotaph','tick':tick,'op':json.dumps(op) if op else None,'error':err,'paid':paid,'bytes':len(payload),'vsize':raw.get('vsize')}

def upsert_candidate(db,txid,parsed,fee_rate=None,seen=None):
    db.execute("""insert into mempool(txid,seen,kind,tick,op,error,fee_rate,vsize,bytes,source,paid)
    values(?,?,?,?,?,?,?,?,?,'scan',?) on conflict(txid) do update set kind=excluded.kind,tick=excluded.tick,op=excluded.op,error=excluded.error,
    fee_rate=coalesce(excluded.fee_rate,mempool.fee_rate),vsize=excluded.vsize,bytes=excluded.bytes,paid=excluded.paid""",
    (txid,seen or int(time.time()),parsed['kind'],parsed['tick'],parsed['op'],parsed['error'],fee_rate,parsed['vsize'],parsed['bytes'],parsed['paid']))

def _remove(db,table,ids):
    for i in range(0,len(ids),400):
        part=ids[i:i+400]
        db.execute(f"delete from {table} where txid in ({','.join('?' for _ in part)})",part)

def scan(rpc,store,checked,budget,state=None,*,max_seconds=10,max_rpc=100,interval=60):
    db=store.db;db.executescript(SCHEMA)
    started=int(time.time());clock=time.monotonic();logical=0;processed=attempted=failed=found=0
    actual_before=getattr(rpc,'total_requests',0);retry_before=getattr(rpc,'total_retries',0)
    prior_deadline=getattr(rpc,'deadline',None);prior_budget=getattr(rpc,'request_budget',None)
    rpc.deadline=clock+max_seconds;rpc.request_budget=max_rpc
    status='running';note=None;retry_after=0
    settings={'version':2,'enabled':True,'interval_seconds':interval,'time_budget_seconds':max_seconds,'rpc_budget':max_rpc,'tx_budget':budget,'persistent':True}
    previous={k:json.loads(v) for k,v in db.execute('select key,value from node')}.get('scanner') or {}
    def call(method,*params):
        nonlocal logical
        if logical>=max_rpc or time.monotonic()-clock>=max_seconds:raise RpcLimit('Scan budget reached.',code='budget')
        logical+=1
        return rpc.call(method,*params)
    def progress(snapshot_at=None):
        total=db.execute('select count(*) from mempool_scan_cache').fetchone()[0]
        done=db.execute('select count(*) from mempool_scan_cache where checked_at is not null').fetchone()[0]
        errors=db.execute('select count(*) from mempool_scan_cache where checked_at is null and failures>0').fetchone()[0]
        rpc_used=getattr(rpc,'total_requests',0)-actual_before if hasattr(rpc,'total_requests') else logical
        report={**settings,'status':status,'snapshot_at':snapshot_at if snapshot_at is not None else previous.get('snapshot_at'),
          'last_progress_at':int(time.time()),'snapshot_transactions':total,'inspected_transactions':done,'backlog':total-done,
          'coverage_percent':round(done*100/total,2) if total else 100.0,'snapshot_complete':done==total and snapshot_at is not None,
          'retry_pending':errors,'cycle_attempted':attempted,'cycle_inspected':processed,'cycle_found':found,
          'cycle_rpc_requests':rpc_used,'total_scan_rpc_requests':int(previous.get('total_scan_rpc_requests',0))+rpc_used,'cycle_retries':getattr(rpc,'total_retries',0)-retry_before,
          'cycle_seconds':round(time.monotonic()-clock,3),'note':note,'retry_after_seconds':retry_after}
        store.put_node(scanner=report,mempool_enabled=True)
        return report
    try:
        # Snapshot first. Cache/mempool rows are never pruned when snapshot RPC fails.
        txids=call('getrawmempool',False)
        if not isinstance(txids,list) or any(not isinstance(t,str) or len(t)!=64 or any(c not in '0123456789abcdef' for c in t) for t in txids):raise RuntimeError('Invalid node mempool snapshot.')
        live=set(txids);snapshot_at=int(time.time());info={}
        try:info=call('getmempoolinfo')
        except RuntimeError as exc:
            if getattr(exc,'code',None)==429:raise
        cached={r[0] for r in db.execute('select txid from mempool_scan_cache')}
        db.execute('begin immediate')
        try:
            _remove(db,'mempool_scan_cache',list(cached-live))
            db.executemany('insert or ignore into mempool_scan_cache(txid,first_seen) values(?,?)',[(t,snapshot_at) for t in live-cached])
            # Preserve API broadcasts created during/after this snapshot, until the next observation.
            stale=[t for t,seen,source in db.execute('select txid,seen,source from mempool') if t not in live and (source!='api' or seen<started)]
            _remove(db,'mempool',stale)
            db.execute('commit')
        except BaseException:db.execute('rollback');raise
        checked.clear();checked.update(r[0] for r in db.execute('select txid from mempool_scan_cache where checked_at is not null'))
        progress(snapshot_at)
        queue=db.execute('select txid,failures from mempool_scan_cache where checked_at is null and next_retry<=? order by first_seen,txid limit ?',(int(time.time()),max(0,int(budget)))).fetchall()
        for txid,failures in queue:
            if logical>=max_rpc or time.monotonic()-clock>=max_seconds:status='budget_limited';break
            attempted+=1
            try:
                raw=call('getrawtransaction',txid,True)
                if not isinstance(raw,dict) or raw.get('txid')!=txid:raise RuntimeError('Transaction response mismatch.')
                parsed=candidate(raw,state)
            except RuntimeError as exc:
                if getattr(exc,'code',None)=='budget':status='budget_limited';attempted-=1;break
                failed+=1
                delay=min(300,10*2**min(failures,5))
                if getattr(exc,'code',None)==429:delay=max(delay,int(getattr(exc,'retry_after',5)));status='rate_limited';retry_after=delay;note='Provider rate limit; scan paused.'
                db.execute('update mempool_scan_cache set failures=failures+1,next_retry=? where txid=?',(int(time.time())+delay,txid))
                if status=='rate_limited':break
                continue
            except (ValueError,KeyError,TypeError,OverflowError):
                failed+=1;db.execute('update mempool_scan_cache set failures=failures+1,next_retry=? where txid=?',(int(time.time())+min(300,10*2**min(failures,5)),txid));continue
            fee_rate=None
            if parsed:
                try:
                    entry=call('getmempoolentry',txid)
                    fee_rate=round(float(entry['fees']['base'])*1e8/entry['vsize'],2)
                except RuntimeError as exc:
                    if getattr(exc,'code',None)==429:status='rate_limited';retry_after=int(getattr(exc,'retry_after',5));note='Provider rate limit; scan paused.'
                except (KeyError,TypeError,ZeroDivisionError):pass
            # Atomic checkpoint per successful transaction, including negative matches.
            db.execute('begin immediate')
            try:
                if parsed:
                    upsert_candidate(db,txid,parsed,fee_rate)
                db.execute('update mempool_scan_cache set checked_at=?,failures=0,next_retry=0,is_tapseal=?,raw_json=? where txid=?',(int(time.time()),int(parsed is not None),json.dumps(raw) if parsed else None,txid))
                db.execute('commit')
            except BaseException:db.execute('rollback');raise
            checked.add(txid);processed+=1;found+=int(parsed is not None)
            if processed%25==0:progress(snapshot_at)
            if status=='rate_limited':break
        # A cached mint may have been seen before its token deployed. Refresh its decoded payment locally.
        for txid,raw_text in db.execute('select txid,raw_json from mempool_scan_cache where is_tapseal=1').fetchall():
            parsed=candidate(json.loads(raw_text),state)
            if parsed:upsert_candidate(db,txid,parsed)
        if status=='running':status='partial' if db.execute('select count(*) from mempool_scan_cache where checked_at is null').fetchone()[0] else 'caught_up'
        report=progress(snapshot_at)
        result={'size':len(live),'node_size':info.get('size'),'bytes':info.get('bytes'),'usage':info.get('usage'),
          'min_fee':round(float(info['mempoolminfee'])*1e5,2) if info.get('mempoolminfee') is not None else None,
          'scanned':processed,'backlog':report['backlog'],'found':found,'snapshot_at':snapshot_at,'inspected':report['inspected_transactions'],'rpc_requests':report['cycle_rpc_requests']}
        store.put_node(mempool=result,mempool_updated_at=snapshot_at)
        return result
    except RuntimeError as exc:
        status='rate_limited' if getattr(exc,'code',None)==429 else 'error'
        note='Snapshot unavailable; prior scan cache retained.'
        retry_after=int(getattr(exc,'retry_after',0))
        progress()
        raise
    finally:
        rpc.deadline=prior_deadline;rpc.request_budget=prior_budget
