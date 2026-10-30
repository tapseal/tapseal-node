// Coverage refers to the last node snapshot, never every node's current mempool.
function scannerStatus(db,now=Math.floor(Date.now()/1000)) {
  const node=db.node(),s=node.scanner||{};
  const configured=typeof node.mempool_enabled==='boolean';
  const enabled=node.mempool_enabled===true;
  const snapshot=s.snapshot_at||null,progress=s.last_progress_at||null;
  const interval=Number(s.interval_seconds||60),threshold=Math.max(60,interval*3+Number(s.time_budget_seconds||10));
  const age=snapshot?Math.max(0,now-snapshot):null;
  const stale=enabled&&(age===null||age>threshold||s.status==='error'||s.status==='rate_limited');
  const total=s.snapshot_transactions??null,done=s.inspected_transactions??null;
  return {ok:true,version:s.version||1,configured,enabled,persistent:s.persistent===true,
    status:!enabled?(configured?'disabled':'unknown'):stale?(s.status==='rate_limited'?'rate_limited':'stale'):s.status||'starting',
    updated_at:enabled?snapshot:null,age_seconds:enabled?age:null,progress_age_seconds:progress?Math.max(0,now-progress):null,
    stale,complete:false,complete_for_snapshot:enabled&&!stale&&s.snapshot_complete===true,
    snapshot_transactions:enabled?total:null,inspected_transactions:enabled?done:null,
    backlog:enabled?s.backlog??null:null,coverage_percent:enabled?s.coverage_percent??null:null,
    retry_pending:enabled?s.retry_pending??0:null,
    cached_inspected_transactions:done,
    interval_seconds:interval,tx_budget:s.tx_budget??null,rpc_budget:s.rpc_budget??null,time_budget_seconds:s.time_budget_seconds??null,
    cycle_rpc_requests:s.cycle_rpc_requests??0,total_scan_rpc_requests:s.total_scan_rpc_requests??0,
    retry_after_seconds:s.retry_after_seconds||0,
    note:!enabled?'Background scan disabled. Only locally recorded broadcasts may be present.':stale?'Last observed snapshot is stale or unavailable.':'Coverage describes this node snapshot only; pending supply is not reserved.'};
}
module.exports={scannerStatus};
