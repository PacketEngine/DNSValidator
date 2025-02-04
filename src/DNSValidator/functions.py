import sys
import string
import random
import logging
import dns.resolver
import pathlib as pl

from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, wait

from .environment import baselinechecks, baselinesrvs, nxdomainchecks
from .CustomLogger import colors as c

# Configure logging
logger = logging.getLogger('DNSValidator')
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Generate a random string of specified length
def get_rand_str(lng: int) -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(lng))

# Get baseline DNS servers
def get_baselines(rootDom: str, servers: Optional[List[str]] = baselinesrvs, checks: Optional[List[str]] = baselinechecks) -> tuple:
    logger.info('Checking baseline servers...', extra={'msgC': ''})
    baselines = {}

    for server in servers:
        baselines[server] = []
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server]
        resolver.timeout = 1
        resolver.lifetime = 3

        for target in checks:
            d = {}

            try:
                rans = resolver.resolve(target, 'A')
                d['ipaddr'] = str(rans[0])
            except dns.exception.Timeout:
                logger.error(f'Baseline server timeout {server}')
                continue
            except Exception as e:
                logger.error(f'Error resolving {target} on {server}: {e}')
                continue

            try:
                resolver.resolve(f'{get_rand_str(10)}.{target}', 'A')
                d['nxdomain'] = False
            except dns.resolver.NXDOMAIN:
                d['nxdomain'] = True
            except dns.exception.Timeout:
                logger.error(f'Baseline server timeout {server}')
                continue
            except Exception as e:
                logger.error(f'Error resolving NXDOMAIN for {target} on {server}: {e}')
                continue

            baselines[server].append({target: d})

    # Safely iterate over all entries to extract the baseline for rootDom
    ipset = {
        entry[rootDom]['ipaddr']
        for server in baselines if baselines[server]
        for entry in baselines[server]
        if rootDom in entry and 'ipaddr' in entry[rootDom]
    }
    nxset = {
        entry[rootDom]['nxdomain']
        for server in baselines if baselines[server]
        for entry in baselines[server]
        if rootDom in entry and 'nxdomain' in entry[rootDom]
    }

    try:
        assert len(ipset) == 1 and len(nxset) == 1 and list(nxset)[0] is True
        return baselines, list(ipset)[0]
    except AssertionError:
        logger.critical(f'Baseline validation failed. IP Set: {ipset}, NX Set: {nxset}')
        sys.exit(1)

# Validate individual DNS server
def check_server(server: str, rootDom: str) -> Optional[str]:
    srvstr = f'{c["cyan"]}{server}{c["reset"]}'
    logger.info(f'Checking server {srvstr}', extra={'msgC': ''})

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]

    nxstr = get_rand_str(10)

    # Validate NXDOMAIN checks
    for nxdomain in nxdomainchecks:
        try:
            resolver.resolve(f'{nxstr}.{nxdomain}', 'A')
            logger.warning(f'DNS poisoning detected, skipping server {srvstr}')
            return None
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            logger.error(f'Error checking DNS poisoning on server {srvstr}: {e}')
            return None

    # Validate root-domain NXDOMAIN
    try:
        resolver.resolve(f'{nxstr}.{rootDom}', 'A')
    except dns.resolver.NXDOMAIN:
        pass
    except dns.exception.Timeout:
        logger.error(f'IP Address validation timeout on server {srvstr}')
        return None
    except Exception as e:
        logger.error(f'Error validating server {srvstr}: {e}')
        return None

    # Validate root-domain IP
    try:
        rans = resolver.resolve(rootDom, 'A')
        if str(rans[0]) == goodip:
            logger.info(f'Successfully validated server {srvstr}', extra={'msgC': c["green"]})
            return server
        else:
            logger.error(f'Invalid response, skipping server {srvstr}')
            return None
    except dns.exception.Timeout:
        logger.error(f'IP Address validation timeout on server {srvstr}')
        return None
    except Exception as e:
        logger.error(f'Error validating server {srvstr}: {e}')
        return None

# Main function to run validation
def run(servers: List[str], workers: int, rootDom: str, fileName: str, vocal: bool = False, silent: bool = False) -> None:
    global quiet, verbose, goodip
    quiet = silent
    verbose = vocal

    _, goodip = get_baselines(rootDom)

    futures = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for server in servers:
            futures.append(executor.submit(check_server, server, rootDom))

    done, _ = wait(futures)

    validServers = [future.result() for future in done if future.result()]

    if validServers:
        with pl.Path(fileName).open('w') as fout:
            fout.writelines(f'{server}\n' for server in validServers)
