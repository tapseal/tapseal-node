"""Rate-limited RPC with bounded retries and scan-local request/time budgets."""
import base64,json,os,time,urllib.error,urllib.request
from collections import deque
from email.utils import parsedate_to_datetime

class RpcLimit(RuntimeError):
    def __init__(self,message,code=None,retry_after=0):
        super().__init__(message);self.code=code;self.retry_after=retry_after

class Rpc:
    def __init__(self,url,user='',password='',bearer='',rps=20):
        self.url=url;self.seq=0;self.delay=1/max(.1,float(rps));self.last=0.0
        self.lat=deque(maxlen=50);self.headers={'Content-Type':'application/json','User-Agent':'tapseal-indexer/2'}
        if bearer:self.headers['Authorization']='Bearer '+bearer
        elif user or password:self.headers['Authorization']='Basic '+base64.b64encode(f'{user}:{password}'.encode()).decode()
        self.timeout=max(1,min(60,float(os.getenv('RPC_TIMEOUT','60'))))
        self.max_retries=max(0,min(3,int(os.getenv('RPC_RETRIES','1'))))
        self.deadline=None;self.request_budget=None;self.cooldown_until=0.0
        self.total_requests=0;self.total_retries=0;self.rate_limits=0

    def _wait(self,seconds):
        if self.deadline is not None and time.monotonic()+seconds>=self.deadline:raise RpcLimit('Scan time budget reached.',code='budget')
        if seconds>0:time.sleep(seconds)

    def call(self,method,*params):
        self.seq+=1
        data=json.dumps({'jsonrpc':'1.0','id':self.seq,'method':method,'params':list(params)}).encode()
        req=urllib.request.Request(self.url,data=data,headers=self.headers)
        start=time.monotonic()
        for attempt in range(self.max_retries+1):
            now=time.monotonic()
            if self.deadline is not None and now>=self.deadline:raise RpcLimit('Scan time budget reached.',code='budget')
            if self.request_budget is not None and self.request_budget<=0:raise RpcLimit('Scan RPC budget reached.',code='budget')
            self._wait(max(0,self.delay-(now-self.last),self.cooldown_until-now))
            timeout=self.timeout
            if self.deadline is not None:timeout=min(timeout,max(.01,self.deadline-time.monotonic()))
            if self.request_budget is not None:self.request_budget-=1
            self.last=time.monotonic();self.total_requests+=1
            if attempt:self.total_retries+=1
            retry=False
            try:
                with urllib.request.urlopen(req,timeout=timeout) as response:payload=json.loads(response.read())
            except urllib.error.HTTPError as exc:
                if exc.code==429:
                    raw=exc.headers.get('Retry-After','5') if exc.headers else '5'
                    try:wait=float(raw)
                    except ValueError:
                        try:wait=parsedate_to_datetime(raw).timestamp()-time.time()
                        except Exception:wait=5
                    wait=max(1,min(300,wait));self.rate_limits+=1;self.cooldown_until=time.monotonic()+wait
                    raise RpcLimit('Bitcoin RPC rate limited (HTTP 429).',code=429,retry_after=wait) from None
                if exc.code in (502,503,504):retry=True
                else:
                    try:payload=json.loads(exc.read())
                    except (ValueError,UnicodeError):raise RpcLimit(f'Bitcoin RPC HTTP {exc.code}.',code=exc.code) from None
            except (urllib.error.URLError,TimeoutError,OSError):retry=True
            except (ValueError,UnicodeError):raise RpcLimit('Bitcoin RPC returned invalid JSON.') from None
            if retry:
                if attempt<self.max_retries:self._wait(2**attempt);continue
                raise RpcLimit('Bitcoin RPC temporarily unavailable.')
            self.lat.append((time.monotonic()-start)*1000)
            if not isinstance(payload,dict):raise RpcLimit('Bitcoin RPC returned an invalid response.')
            if payload.get('error'):
                err=payload['error'];code=err.get('code') if isinstance(err,dict) else None
                raise RpcLimit(f'Bitcoin RPC {method} error ({code}).',code=code)
            if 'result' not in payload:raise RpcLimit('Bitcoin RPC response is missing result.')
            return payload['result']

    def latency_ms(self):return round(sum(self.lat)/len(self.lat),1) if self.lat else None
