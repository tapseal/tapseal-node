#!/usr/bin/env python3
import io,json,unittest,urllib.error
from email.message import Message
from unittest.mock import patch
from persistent_rpc import Rpc,RpcLimit

class Clock:
    def __init__(self):self.value=100.0
    def monotonic(self):return self.value
    def sleep(self,seconds):self.value+=seconds

def response(value):return io.BytesIO(json.dumps({'result':value,'error':None}).encode())

class RpcChecks(unittest.TestCase):
    def test_rate_limit_json_body_still_honors_retry_after(self):
        headers=Message();headers['Retry-After']='12'
        error=urllib.error.HTTPError('https://example.invalid',429,'limited',headers,io.BytesIO(b'{"error":{"code":429}}'))
        rpc=Rpc('https://example.invalid',rps=10)
        with patch('persistent_rpc.urllib.request.urlopen',side_effect=error):
            with self.assertRaises(RpcLimit) as ctx:rpc.call('getrawmempool',False)
        self.assertEqual(ctx.exception.code,429);self.assertEqual(ctx.exception.retry_after,12);self.assertEqual(rpc.total_requests,1)
    def test_retries_count_against_request_budget(self):
        rpc=Rpc('https://example.invalid');rpc.request_budget=1
        clock=Clock()
        with patch('persistent_rpc.time.monotonic',clock.monotonic),patch('persistent_rpc.time.sleep',clock.sleep),patch('persistent_rpc.urllib.request.urlopen',side_effect=urllib.error.URLError('down')):
            with self.assertRaises(RpcLimit) as ctx:rpc.call('getrawmempool',False)
        self.assertEqual(ctx.exception.code,'budget');self.assertEqual(rpc.total_requests,1)
    def test_every_http_attempt_obeys_rate_limit(self):
        rpc=Rpc('https://example.invalid',rps=2);clock=Clock();times=[]
        def fetch(*args,**kwargs):times.append(clock.value);return response(1)
        with patch('persistent_rpc.time.monotonic',clock.monotonic),patch('persistent_rpc.time.sleep',clock.sleep),patch('persistent_rpc.urllib.request.urlopen',fetch):
            rpc.call('one');rpc.call('two');rpc.call('three')
        self.assertGreaterEqual(times[1]-times[0],.5);self.assertGreaterEqual(times[2]-times[1],.5)
    def test_deadline_prevents_retry_backoff_overrun(self):
        rpc=Rpc('https://example.invalid');clock=Clock();rpc.deadline=100.5
        with patch('persistent_rpc.time.monotonic',clock.monotonic),patch('persistent_rpc.time.sleep',clock.sleep),patch('persistent_rpc.urllib.request.urlopen',side_effect=urllib.error.URLError('down')):
            with self.assertRaises(RpcLimit) as ctx:rpc.call('getrawmempool',False)
        self.assertEqual(ctx.exception.code,'budget');self.assertEqual(clock.value,100)
    def test_node_rpc_error_is_not_retried_or_logged_with_credentials(self):
        rpc=Rpc('https://example.invalid/private-token')
        with patch('persistent_rpc.urllib.request.urlopen',return_value=io.BytesIO(b'{"error":{"code":-5,"message":"secret details"},"result":null}')):
            with self.assertRaises(RpcLimit) as ctx:rpc.call('getrawtransaction','txid')
        self.assertEqual(rpc.total_requests,1);self.assertEqual(ctx.exception.code,-5);self.assertNotIn('private-token',str(ctx.exception));self.assertNotIn('secret details',str(ctx.exception))
    def test_cooldown_applies_to_subsequent_calls(self):
        rpc=Rpc('https://example.invalid');clock=Clock();rpc.cooldown_until=110
        with patch('persistent_rpc.time.monotonic',clock.monotonic),patch('persistent_rpc.time.sleep',clock.sleep),patch('persistent_rpc.urllib.request.urlopen',return_value=response(1)):
            self.assertEqual(rpc.call('getblockcount'),1)
        self.assertEqual(clock.value,110)

if __name__=='__main__':unittest.main()
