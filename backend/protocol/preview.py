#!/usr/bin/env python3
"""Read-only TAPSEAL protocol simulation. Never verifies Bitcoin signatures."""
import copy,json,sqlite3,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'protocol'),str(ROOT/'indexer')]
import tapseal as T
import tapseal_indexer as IX

def preview(path, request):
    db=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True,timeout=5)
    try:
        db.execute('BEGIN')
        holder=IX.Store.__new__(IX.Store); holder.db=db
        state=holder.load_state()
        tip=db.execute('select height,hash from blocks order by height desc limit 1').fetchone()
        node={k:json.loads(v) for k,v in db.execute('select key,value from node')}
        if not tip: raise ValueError('Indexer has no confirmed tip.')
        tx=request['tx']
        tx['vin']=[{**v,'witness':[bytes.fromhex(w) for w in v['witness']]} for v in tx['vin']]
        tx['vout']=[{**o,'spk':bytes.fromhex(o['spk'])} for o in tx['vout']]
        owners=[bytes.fromhex(k) for k in request.get('owners',[])]
        if not owners: raise ValueError('Expected recipient/owner keys are required.')
        before=copy.deepcopy(state)
        payloads=[T.payload_from_script(o['spk']) for o in tx['vout']]
        payloads=[p for p in payloads if p is not None]
        if len(payloads)!=1: raise ValueError('Preview requires exactly one TAPSEAL payload.')
        op=T.decode(payloads[0]); wanted=request.get('expected',{})
        errors=[];warnings=[]
        if wanted.get('op') and op['op']!=wanted['op']: errors.append('Operation differs from requested action.')
        ticks=[t['tick'] for t in op['ticks']] if op['op']=='transfer' else [op.get('tick')]
        if wanted.get('tick') and ticks!=[wanted['tick'].upper()]: errors.append('Token differs from requested token.')
        for v in tx['vin']:
            seal=state.seals.get(v['prevout'])
            if seal and seal.lock:
                if tx.get('locktime',0)<seal.lock or v.get('sequence',0xffffffff)==0xffffffff or tip[0]+1<=tx.get('locktime',0):
                    errors.append('Locked seal cannot be spent in the next block.')
        evs=T.apply_tx(state,tx,tip[0]+1)
        for e in evs:
            if e['kind'] in ('invalid','cenotaph','lost','lost-auth'): errors.append(e.get('detail') or e['kind'])
            if e['kind']=='burn' and wanted.get('op')!='burn': errors.append('Unexpected token burn.')
        if not any(e['kind']==op['op'] for e in evs): errors.append('Requested operation produces no accepted effect.')
        created=[s for k,s in state.seals.items() if k.startswith(tx['txid']+':')]
        for seal in created:
            if not any(T.seal_spk(seal.tick,key,seal.lock,seal.auth)==seal.spk for key in owners):
                errors.append('A receiving seal does not match the expected wallet keys.')
        if op['op']=='transfer' and wanted.get('recipients'):
            for i,recipient in enumerate(wanted['recipients'],1):
                seal=state.seals.get(tx['txid']+':'+str(i))
                if not seal or seal.amt!=int(recipient['atoms']) or seal.lock!=int(recipient.get('lock',0)) or seal.spk!=T.seal_spk(wanted['tick'].upper(),bytes.fromhex(recipient['owner']),int(recipient.get('lock',0))):
                    errors.append('Recipient allocation differs from requested amount, address or lock.')
        if op['op']=='operator':
            if wanted.get('operator_owner') != op['owner'] or int(wanted.get('max_atoms',-1)) != op['max'] or int(wanted.get('expiry',-1)) != op['expiry']:
                errors.append('Operator approval differs from requested wallet, quota or expiry.')
        if op['op']=='mint':
            mint=next((e for e in evs if e['kind']=='mint'),None)
            if wanted.get('atoms') is not None and (mint is None or mint['amt']!=int(wanted['atoms'])): errors.append('Mint allocation changed. Rebuild the quote before signing.')
            tok=before.tokens.get(op['tick'])
            if tok and (op.get('pass') or op.get('operator')) and not wanted.get('allowlist'): errors.append('Unexpected allowlist pass in this mint.')
            if tok and tok.mode!='fair':
                paid=sum(o['value'] for i,o in enumerate(tx['vout']) if i!=op['vout'] and o['spk']==tok.treasury_spk)
                cap=tok.params.get('cap',0)
                if cap and paid>cap: errors.append('Treasury payment exceeds the mint cap.')
                if wanted.get('pay_sats') is not None and paid!=int(wanted['pay_sats']): errors.append('Treasury payment differs from requested payment.')
            warnings.append('Pending competition is not replayed by this preview; supply is not reserved.')
        if op['op']=='burn' and wanted.get('atoms') is not None:
            burnt=sum(e['amt'] for e in evs if e['kind']=='burn')
            if burnt!=int(wanted['atoms']): errors.append('Burn amount differs from request.')
        if op['op']=='deploy':
            if wanted.get('treasury_script') is not None and state.tokens.get(op['tick']) and state.tokens[op['tick']].treasury_spk.hex()!=wanted['treasury_script']:errors.append('Deployment treasury differs from request.')
            if wanted.get('pow') is not None and op.get('pow')!=wanted['pow']:errors.append('Deployment work rules differ from request.')
            for request_key,op_key in [('max_atoms','max'),('dec','dec'),('lim_atoms','lim')]:
                if wanted.get(request_key) is not None and op.get(op_key)!=int(wanted[request_key]): errors.append('Deployment parameters differ from request: '+request_key)
            if wanted.get('mode') is not None and op['mode']!=wanted['mode']: errors.append('Deployment mode differs from request.')
        age=max(0,int(time.time())-int(node.get('updated_at') or 0))
        lag=node.get('lag')
        if age>180 or lag is None or lag>1: errors.append('Indexer state is stale or behind the node; wait for synchronization.')
        pending_rows=db.execute("select paid,op from mempool where kind='mint' and tick=?",(op.get('tick'),)).fetchall()
        demand=0;unknown=0;available=None
        if op['op']=='mint' and op['tick'] in before.tokens:
            token=before.tokens[op['tick']]
            remaining=max(0,token.max-token.minted)
            for payment,pending_op in pending_rows:
                if payment is None and token.mode!='fair': unknown+=1;continue
                quoted=T.mint_amount(token,int(payment or 0),allowlist=bool(json.loads(pending_op or '{}').get('operator')))
                demand+=min(quoted,remaining)
            available=max(0,remaining-demand)
            allocation=sum(e['amt'] for e in evs if e['kind']=='mint')
            if allocation>available: errors.append('Detected pending demand leaves insufficient estimated supply. Wait or reduce the mint.')
            if unknown: errors.append('Known pending mints have unknown payment amounts. Wait for confirmation.')
        coverage={'enabled':node.get('mempool_enabled'), 'updated_at':node.get('mempool_updated_at'), 'backlog':(node.get('mempool') or {}).get('backlog'), 'known_pending_mints':len(pending_rows), 'requested_atoms_estimate':str(demand), 'remaining_atoms_estimate':str(available) if available is not None else None, 'complete':False}
        def seal_json(s): return {'outpoint':s.outpoint,'tick':s.tick,'atoms':str(s.amt),'lock':s.lock,'authority':bool(s.auth),'script':s.spk.hex()}
        effects={'spent':[seal_json(s) for k,s in before.seals.items() if k not in state.seals], 'created':[seal_json(s) for s in created], 'events':[{**e,'amt':str(e['amt'])} for e in evs]}
        return {'valid':not errors,'errors':list(dict.fromkeys(errors)), 'warnings':warnings,'txid':tx['txid'],'operation':op['op'],'indexed_height':tip[0],'indexed_hash':tip[1],'telemetry_age_seconds':age,'pending':coverage,'effects':effects,'signature_checks':'Not performed by the protocol simulator.'}
    finally: db.close()
if __name__=='__main__':
    try:
        request=json.load(sys.stdin)
        print(json.dumps(preview(sys.argv[1],request)))
    except Exception as e:
        print(json.dumps({'valid':False,'errors':[str(e)],'warnings':[]}))
