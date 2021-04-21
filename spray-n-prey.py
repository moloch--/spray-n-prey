#!/usr/bin/env python3

import asyncio
import argparse

from ipaddress import ip_network, ip_address, IPv4Address
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Generator


DEFAULT_PORTS = {
    'ssh': 22,
    'smb': 445
}


class TCPScanner(object):

    def __init__(self, open_queues: Dict[int, asyncio.Queue], timeout=5.0):
        self.timeout = timeout
        self.tcp_queue = asyncio.Queue()
        self.open_queues = open_queues
        self.tcp_scan_completed = asyncio.Event()

    def _targets(self, targets: List[str]) -> Generator[IPv4Address, None, None]:
        ''' Lazily generate hosts in ip ranges '''
        for target in targets:
            for host in ip_network(target).hosts():
                yield str(host)

    async def scan(self, targets: List[str]) -> None:
        ''' Scans a list of target networks/ips and ports, results are put into open queue '''
        tasks = []
        # for _ in range(self.max_workers):
        #     tasks.append(asyncio.create_task(self._task_worker()))

        for ip in self._targets(targets):
            for port in self.open_queues.keys():
                await self.tcp_queue.put((ip, port))
                tasks.append(asyncio.create_task(self._task_worker()))
        print("[manager] all hosts in queue")
        await self.tcp_queue.join()
        print("[manager] all workers have completed")
        self.tcp_scan_completed.set()

    async def _task_worker(self):
        while True:
            ip, port = (await self.tcp_queue.get())
            print("[worker] %s:%d" % (ip, port))
            conn = asyncio.open_connection(ip, port)
            try:
                await asyncio.wait_for(conn, self.timeout)
            except (asyncio.TimeoutError, ConnectionRefusedError):
                pass
            else:
                self.open_queues[port].put_nowait((ip, port))
            finally:
                self.tcp_queue.task_done()


class LoginScanner(object):

    def __init__(self, credentials, timeout=1000, max_workers=32):
        self.credentails = credentials
        self.timeout = timeout
        self.max_workers = max_workers
        self.thread_pool = ThreadPoolExecutor(max_workers=self.max_workers)


class SSHLoginScanner(LoginScanner):

    pass


class SMBLoginScanner(LoginScanner):

    pass



async def main(args):
    # Create per-port/service queues
    ports = [DEFAULT_PORTS[service] for service in args.services]
    open_queues = dict((port, asyncio.Queue(),) for port in ports)

    # Start the TCP scanner
    tcp_scanner = TCPScanner(open_queues, args.timeout)
    tcp_scan = tcp_scanner.scan(args.targets)
    await tcp_scan

    print('open queues: %r' % tcp_scanner.open_queues)



class ValidatServicesAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        for service in values:
            if service not in DEFAULT_PORTS:
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
        default=128
    )
    parser.add_argument('--timeout', '-T',
        help='connection timeout in seconds',
        dest='timeout',
        type=float,
        default=2.0
    )
    parser.add_argument('--targets', '-t',
        help='target ip cidr range(s) or ip address(es)',
        dest='targets',
        nargs='*',
        required=True,
    )
    parser.add_argument('--services', '-s',
        help='list of services to scan/spray',
        dest='services',
        nargs='*',
        default=list(DEFAULT_PORTS.keys()),
        action=ValidatServicesAction
    )
    asyncio.run(main(parser.parse_args()))

