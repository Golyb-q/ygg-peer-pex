#!/usr/bin/env python3
"""Discover, persist, prune and exchange working Yggdrasil peering URIs via NodeInfo."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

CONFIG_CANDIDATES = (Path('/etc/yggdrasil.conf'), Path('/etc/yggdrasil/yggdrasil.conf'))


def detect_config(explicit=None):
    """Prefer explicit path, then effective systemd ExecStart, then known paths."""
    if explicit is not None:
        path = Path(explicit).absolute()
    else:
        path = None
        try:
            result = run('systemctl', 'show', 'yggdrasil.service', '-p', 'ExecStart', '--value')
            if result.returncode == 0:
                matches = re.findall(r'-useconffile(?:=|\s+)(?:"([^"\n]+)"|([^\s;]+))', result.stdout)
                paths = {a or b for a, b in matches}
                if len(paths) == 1:
                    path = Path(paths.pop())
                elif len(paths) > 1:
                    raise RuntimeError('Multiple service config paths; specify --config')
        except (OSError, subprocess.TimeoutExpired):
            pass
        if path is None:
            candidates = [p for p in CONFIG_CANDIDATES if p.is_file()]
            if len(candidates) != 1:
                raise RuntimeError('Cannot uniquely locate Yggdrasil config; specify --config')
            path = candidates[0]
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f'Config missing or symlinked: {path}')
    return path



def run(*args, timeout=20):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def valid_uri(uri):
    if uri != uri.strip() or re.search(r'\s', uri):
        return False
    try:
        parsed = urlsplit(uri)
        return (parsed.scheme in {'tcp', 'tls', 'quic'}
                and bool(parsed.hostname)
                and parsed.port is not None
                and 1 <= parsed.port <= 65535
                and not parsed.path and not parsed.query and not parsed.fragment
                and not parsed.username and not parsed.password)
    except ValueError:
        return False


# Yggdrasil's overlay 200::/7 is not an Internet transport address.
YGG_OVERLAY = ipaddress.ip_network('200::/7')

def is_public_transport(uri, dns_cache=None):
    """Exclude overlay, local and non-global transport destinations before addPeer.

    DNS hostnames are resolved so a .com pointing at an overlay/private address
    cannot evade this check. At least one globally reachable address is required.
    Note: a globally scoped IP does not guarantee actual Internet reachability.
    """
    if not valid_uri(uri):
        return False
    parsed = urlsplit(uri)
    host = parsed.hostname
    if host.endswith(('.ygg', '.localhost', '.local', '.internal', '.invalid', '.test')):
        return False

    def good_ip(ip):
        address = ipaddress.ip_address(ip)
        return address.is_global and not (isinstance(address, ipaddress.IPv6Address) and address in YGG_OVERLAY)

    try:
        return good_ip(host)
    except ValueError:
        pass

    if dns_cache is None:
        dns_cache = {}
    if host not in dns_cache:
        try:
            # getaddrinfo is only a DNS preflight; Yggdrasil still performs
            # its own connection and determines actual reachability.
            answers = socket.getaddrinfo(host, parsed.port, type=socket.SOCK_STREAM)
            dns_cache[host] = [item[4][0] for item in answers]
        except (socket.gaierror, OSError):
            dns_cache[host] = []
    return any(good_ip(ip) for ip in dns_cache[host])


def peers_section(config):
    """Return multiline Peers body boundaries (supported config layout)."""
    pattern = re.compile(r'(?m)^([ \t]*)(?:Peers|"Peers")\s*:\s*\[\s*\n')
    matches = list(pattern.finditer(config))
    if len(matches) != 1:
        raise ValueError('Expected exactly one multiline Peers: [ section; config unchanged')
    match = matches[0]
    end_pattern = re.compile(r'(?m)^[ \t]*\][ \t]*,?[ \t]*(?://[^\n]*)?$')
    close = end_pattern.search(config, match.end())
    if not close:
        raise ValueError('Cannot locate end of Peers section; config unchanged')
    return match, close, config[match.end():close.start()]


def configured_uris(config):
    # Exact entries only, not substrings, comments, or text elsewhere in config.
    _match, _close, body = peers_section(config)
    return set(re.findall(r'(?m)^\s*["\']([^"\']+)["\']\s*,?\s*(?:(?://|#).*?)?$', body))


def parse_peer_table(text):
    """Handle bordered, tab-separated and whitespace-separated CLI tables."""
    result = {}
    header = False
    for line in text.splitlines():
        if re.search(r'\bURI\b', line, re.I) and re.search(r'\bState\b', line, re.I):
            header = True
        match = re.match(r'^\s*[│|]?\s*(\S+?)\s*(?:[│|]\s*|\s+)(Up|Down)(?=\s|[│|]|$)', line, re.I)
        if match and valid_uri(match[1]):
            uri, state = match[1], match[2].capitalize()
            if uri in result and result[uri] != state:
                raise RuntimeError(f'Conflicting states for {uri}')
            result[uri] = state
    if not result and not header:
        raise RuntimeError('Unrecognized getPeers table; refusing config changes')
    # An empty or unfamiliar table must not erase PEX or prune peers.
    if not result:
        raise RuntimeError('No recognizable peer rows; refusing config changes')
    return result


def parse_peer_json(text):
    data = json.loads(text)
    if not isinstance(data, dict) or 'peers' not in data:
        raise ValueError('Unknown getPeers JSON shape')
    peers = data['peers']
    if not isinstance(peers, (list, dict)):
        raise ValueError('Unknown peers collection')
    result = {}
    for key, row in (peers.items() if isinstance(peers, dict) else enumerate(peers)):
        if not isinstance(row, dict):
            raise ValueError('Unknown peer row')
        fields = {k.lower(): v for k, v in row.items()}
        uri = fields.get('uri', fields.get('remote', key))
        if not isinstance(uri, str) or not valid_uri(uri):
            continue
        up = fields.get('up', fields.get('state'))
        if isinstance(up, bool):
            state = 'Up' if up else 'Down'
        elif isinstance(up, str) and up.lower() in ('up', 'down'):
            state = up.capitalize()
        else:
            raise ValueError('Unknown peer state')
        if uri in result and result[uri] != state:
            raise ValueError('Conflicting peer states')
        result[uri] = state
    if not result:
        raise ValueError('No recognizable JSON peer rows')
    return result


def peer_states():
    """Prefer machine-readable API; fall back to compatible CLI tables."""
    p = run('yggdrasilctl', '-json', 'getPeers', timeout=20)
    if not p.returncode:
        try:
            return parse_peer_json(p.stdout)
        except ValueError:
            pass
    p = run('yggdrasilctl', 'getPeers', timeout=20)
    if p.returncode:
        raise RuntimeError(p.stderr.strip() or p.stdout.strip() or 'getPeers failed')
    return parse_peer_table(p.stdout)


def prune_config_text(config, to_remove):
    """Remove only complete URI entries inside Peers, preserving other config text.

    Conservative: abort if any selected URI cannot be matched to an exact line.
    """
    match, close, body = peers_section(config)
    lines = body.splitlines(keepends=True)
    entry = re.compile(r"""^([ \t]*)["']([^"']+)["']([ \t]*,?[ \t]*(?:(?://|#)[^\n]*)?)(\r?\n)?$""")
    found = set()
    result = []
    for line in lines:
        m = entry.fullmatch(line)
        if m and m.group(2) in to_remove:
            found.add(m.group(2))
        else:
            result.append(line)
    if found != to_remove:
        raise ValueError('Peer entries changed or cannot be matched; config unchanged')
    return config[:match.end()] + ''.join(result) + config[close.start():]


def prune_down(path, backup_enabled=False, recheck_seconds=3):
    """Remove explicitly Down configured peers, but never all configured peers."""
    if path.is_symlink():
        raise RuntimeError('Refusing to rewrite a symlinked config')
    original = path.read_bytes()
    config = original.decode('utf-8')
    entries = configured_uris(config)
    initial = peer_states()
    candidates = sorted(uri for uri in entries if initial.get(uri) == 'Down')
    if not candidates:
        print('Prune: no configured peers explicitly Down; nothing to remove')
        return False
    print(f'Prune: {len(candidates)} configured Down URI(s) found; rechecking...', flush=True)
    time.sleep(max(0, recheck_seconds))
    latest = peer_states()
    to_remove = {uri for uri in candidates if latest.get(uri) == 'Down'}
    for uri in candidates:
        if uri not in to_remove:
            print(f'  Keeping (state changed or missing): {uri}', flush=True)
    if not to_remove:
        print('Prune: no peers remain Down after recheck')
        return False
    if not any(latest.get(uri) == 'Up' for uri in entries - to_remove):
        print('Prune: refusing to prune without a confirmed Up configured peer', flush=True)
        return False
    # One more read protects against a concurrent change in the config file.
    if path.read_bytes() != original:
        raise RuntimeError('Config changed during prune; aborting')
    updated = prune_config_text(config, to_remove)
    validate_and_replace(path, original, updated, backup_enabled, 'prune')
    for uri in sorted(to_remove):
        print(f'  Removed from config: {uri}', flush=True)
    print(f'Prune: removed {len(to_remove)} Down URI(s); {len(entries-to_remove)} configured URI(s) retained')
    print('NOTE: runtime getPeers is unchanged until service restart; no restart performed.')
    return True


def validate_and_replace(path, original, updated, backup_enabled, tag):
    """Shared guarded atomic configuration update."""
    st = path.stat()
    tempname = None
    try:
        fd, tempname = tempfile.mkstemp(prefix='.ygg-conf-', dir=str(path.parent))
        with os.fdopen(fd, 'wb') as out:
            out.write(updated.encode('utf-8'))
            out.flush()
            os.fsync(out.fileno())
        os.chown(tempname, st.st_uid, st.st_gid)
        os.chmod(tempname, stat.S_IMODE(st.st_mode))
        check = run('yggdrasil', '-normaliseconf', '-useconffile', tempname)
        if check.returncode:
            raise RuntimeError('Yggdrasil rejected modified config: ' + (check.stderr or check.stdout).strip())
        if path.read_bytes() != original:
            raise RuntimeError('Config changed during edit; aborting')
        backup = None
        if backup_enabled:
            backup = path.with_name(f'{path.name}.bak-{time.strftime("%Y%m%d-%H%M%S")}-{os.getpid()}-{tag}')
            with open(backup, 'xb') as out:
                os.fchmod(out.fileno(), 0o600)
                out.write(original)
                out.flush()
                os.fsync(out.fileno())
        os.replace(tempname, path)
        tempname = None
        if backup:
            print(f'Backup: {backup} (mode 0600)')
    finally:
        if tempname and os.path.exists(tempname):
            os.unlink(tempname)


def state_for(uri):
    return peer_states().get(uri)


def insert_peer(config, uri):
    match, close, body = peers_section(config)
    if uri in configured_uris(config):
        return config, False
    has_entries = bool(configured_uris(config))
    indent = match.group(1) + '  '
    addition = f'{indent}"{uri}"' + (',' if has_entries else '') + '\n'
    return config[:match.end()] + addition + config[match.end():], True


def persist(path, uri, backup_enabled=False):
    if path.is_symlink():
        raise RuntimeError('Refusing to rewrite a symlinked config')
    original = path.read_bytes()
    text = original.decode('utf-8')
    updated, changed = insert_peer(text, uri)
    if not changed:
        print('URI already present in config; no file changes')
        return False
    st = path.stat()
    tempname = None
    try:
        fd, tempname = tempfile.mkstemp(prefix='.ygg-conf-', dir=str(path.parent))
        with os.fdopen(fd, 'wb') as f:
            f.write(updated.encode('utf-8'))
            f.flush()
            os.fsync(f.fileno())
        os.chown(tempname, st.st_uid, st.st_gid)
        os.chmod(tempname, stat.S_IMODE(st.st_mode))
        result = run('yggdrasil', '-normaliseconf', '-useconffile', tempname)
        if result.returncode:
            raise RuntimeError('Yggdrasil rejected modified config: ' + (result.stderr or result.stdout).strip())
        backup = None
        if backup_enabled:
            stamp = time.strftime('%Y%m%d-%H%M%S')
            backup = path.with_name(f'{path.name}.bak-{stamp}-{os.getpid()}')
            with open(backup, 'xb') as out:
                os.fchmod(out.fileno(), 0o600)
                out.write(original)
                out.flush()
                os.fsync(out.fileno())
        os.replace(tempname, path)
        tempname = None
        print(f'Saved peer to {path}')
        if backup is not None:
            print(f'Backup: {backup} (mode 0600)')
        return True
    finally:
        if tempname and os.path.exists(tempname):
            os.unlink(tempname)


# Scan every JSON string, not just specific NodeInfo fields. URI syntax still
# undergoes valid_uri() and Internet destination checks before connection.
URI_FINDER = re.compile(
    r'(?i)(?<![a-z0-9+.-])(?:tcp|tls|quic)://(?:\[[0-9a-f:.%]+\]|[a-z0-9_.-]+):[0-9]{1,5}(?![0-9a-z])'
)


def all_json_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from all_json_strings(key)
            yield from all_json_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from all_json_strings(item)


def extract_transport_uris(nodeinfo):
    seen = set()
    for value in all_json_strings(nodeinfo):
        for match in URI_FINDER.finditer(value):
            uri = match.group(0)
            if valid_uri(uri) and uri not in seen:
                seen.add(uri)
                yield uri


def own_public_key():
    """Read our node identity from the running daemon (not from NodeInfo)."""
    try:
        result = run('yggdrasilctl', '-json', 'getSelf', timeout=15)
    except subprocess.TimeoutExpired:
        print('Warning: getSelf timed out; own node cannot be excluded', flush=True)
        return None
    if result.returncode:
        print('Warning: getSelf failed; own node cannot be excluded', flush=True)
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        print('Warning: getSelf did not return JSON; own node cannot be excluded', flush=True)
        return None

    def lookup(value):
        if isinstance(value, dict):
            for field, item in value.items():
                if field.lower() in ('key', 'publickey', 'public_key') and isinstance(item, str):
                    if re.fullmatch(r'[0-9a-fA-F]{64}', item):
                        return item.lower()
            for item in value.values():
                candidate = lookup(item)
                if candidate:
                    return candidate
        elif isinstance(value, list):
            for item in value:
                candidate = lookup(item)
                if candidate:
                    return candidate
        return None

    key = lookup(payload)
    if key is None:
        print('Warning: getSelf has no recognizable public key; own node cannot be excluded', flush=True)
    return key


def discover_uris(max_nodes=None):
    """Read known node keys and search all NodeInfo strings for peering URIs."""
    keys = []
    try:
        r = run('yggdrasilctl', 'getTree', timeout=15)
    except subprocess.TimeoutExpired:
        print('Warning: getTree timed out; skipping', flush=True)
        return
    if r.returncode:
        print('Warning: getTree failed; skipping', flush=True)
        return
    for key in re.findall(r'(?i)\b[0-9a-f]{64}\b', r.stdout):
        key = key.lower()
        if key not in keys:
            keys.append(key)
    local_key = own_public_key()
    if local_key is not None and local_key in keys:
        keys.remove(local_key)
        print('Skipping own node in getTree (getSelf public key)', flush=True)
    if max_nodes is not None:
        keys = keys[:max_nodes]
    print(f'Checking NodeInfo of all {len(keys)} known nodes...', flush=True)
    seen_uris = set()
    for index, key in enumerate(keys, 1):
        try:
            r = run('yggdrasilctl', 'getNodeInfo', f'key={key}', timeout=8)
        except subprocess.TimeoutExpired:
            continue
        if r.returncode:
            continue
        try:
            data = json.loads(r.stdout)
        except json.JSONDecodeError:
            continue
        for uri in extract_transport_uris(data):
            if uri not in seen_uris:
                seen_uris.add(uri)
                print(f'  Found: {uri} (NodeInfo {index}/{len(keys)})', flush=True)
                yield uri


def add_if_working(uri, config, wait, dns_cache=None, backup_enabled=False):
    # Return True if a new working candidate was successfully persisted.
    if uri in configured_uris(config.read_text('utf-8')):
        print(f'Skipping configured peer: {uri}')
        return False
    if not is_public_transport(uri, dns_cache):
        print(f'Skipping non-public or unresolvable transport: {uri}')
        return False
    state = state_for(uri)
    added_now = False
    if state != 'Up':
        if state is None:
            print('Trying:', uri, flush=True)
            r = run('yggdrasilctl', 'addPeer', f'uri={uri}')
            if r.returncode:
                print('  addPeer failed:', (r.stderr or r.stdout).strip(), flush=True)
                return False
            added_now = True
        else:
            print(f'Waiting for known peer ({state}): {uri}', flush=True)
        deadline = time.monotonic() + max(1, wait)
        while time.monotonic() < deadline:
            state = state_for(uri)
            if state == 'Up':
                break
            time.sleep(2)
    if state != 'Up':
        print(f'  Not Up: {uri} ({state})', flush=True)
        # Do not leave failed experimental peerings in the live instance.
        if added_now:
            r = run('yggdrasilctl', 'removePeer', f'uri={uri}')
            if r.returncode:
                print('  Warning: failed to remove unsuccessful peer', flush=True)
        return False
    print(f'  UP! Saving: {uri}', flush=True)
    persist(config, uri, backup_enabled=backup_enabled)
    return True



# A managed PEX stanza is separated from the standard "public" advertisement.
# It contains working *remote* peer URIs, not a claimed listener on this node.
PEX_BEGIN = '# BEGIN ygg-peer-add managed PEX'
PEX_END = '# END ygg-peer-add managed PEX'


def nodeinfo_section(config):
    """Locate one NodeInfo: { ... } block, refusing ambiguous layouts.

    A lightweight brace scanner handles normal JSON/HJSON quoted text and line
    comments; the final result is always validated by yggdrasil itself.
    """
    pattern = re.compile(r'(?m)^[ \t]*(?:NodeInfo|"NodeInfo")\s*:\s*\{')
    matches = list(pattern.finditer(config))
    if len(matches) != 1:
        raise ValueError('Expected exactly one NodeInfo: { ... } section')
    m = matches[0]
    start = config.index('{', m.start(), m.end())
    depth, quote, escaped, comment = 0, None, False, False
    i = start
    while i < len(config):
        ch = config[i]
        if comment:
            if ch == '\n':
                comment = False
            i += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
        elif ch == '#' or (ch == '/' and i+1 < len(config) and config[i+1] == '/'):
            comment = True
            if ch == '/':
                i += 1
        elif ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return m, start, i
        i += 1
    raise ValueError('Unclosed NodeInfo section')


def replace_pex_block(config, uris):
    """Update only our own PEX field. Refuse to overwrite somebody else's PEX."""
    match, start, end = nodeinfo_section(config)
    body = config[start+1:end]
    begin_at, end_at = body.find(PEX_BEGIN), body.find(PEX_END)
    if (begin_at == -1) != (end_at == -1):
        raise ValueError('Incomplete managed PEX markers; leaving config unchanged')
    if begin_at >= 0:
        if body.count(PEX_BEGIN) != 1 or body.count(PEX_END) != 1 or end_at < begin_at:
            raise ValueError('Ambiguous managed PEX markers; leaving config unchanged')
        # Remove whole marker lines, preserving the rest of NodeInfo.
        line_start = body.rfind('\n', 0, begin_at) + 1
        line_end = body.find('\n', end_at)
        if line_end < 0:
            line_end = len(body)
        else:
            line_end += 1
        remainder = body[:line_start] + body[line_end:]
    else:
        remainder = body
        if re.search(r'(?m)^\s*(?:"pex"|pex)\s*:', remainder):
            raise ValueError('NodeInfo already contains an unmanaged pex field')

    # The 16 KiB NodeInfo limit includes other user fields and build metadata.
    # Leave ample headroom; the config validator is an additional safeguard.
    if len(uris) > 64:
        uris = uris[:64]
    pex_json = json.dumps({'internet': uris}, indent=2, ensure_ascii=False)
    indent = match.group(0).split('NodeInfo')[0]
    indent = re.match(r'[ \t]*', match.group(0)).group(0) + '  '
    field = json.dumps('pex') + ': ' + pex_json.replace('\n', '\n' + indent)
    stanza = f'{indent}{PEX_BEGIN}\n{indent}{field}\n{indent}{PEX_END}\n'
    # An empty URIs list clears prior managed PEX to avoid publishing stale data.
    replacement_body = remainder
    if uris:
        replacement_body = remainder.rstrip() + '\n' + stanza
    updated = config[:start+1] + replacement_body + config[end:]
    if len(updated[start:end].encode('utf-8')) > 13500:
        raise ValueError('NodeInfo could be too large; refusing to publish')
    return updated


def active_public_peers():
    """Collect only currently Up, usable Internet transport URIs."""
    dns_cache = {}
    return sorted(uri for uri, state in peer_states().items()
                  if state == 'Up' and is_public_transport(uri, dns_cache))


def publish_active(path, backup_enabled=False):
    """Persist a managed NodeInfo. Needs service restart to become visible."""
    if path.is_symlink():
        raise RuntimeError('Refusing to rewrite a symlinked config')
    original = path.read_bytes()
    config = original.decode('utf-8')
    uris = active_public_peers()
    updated = replace_pex_block(config, uris)
    if updated == config:
        print(f'PEX already current ({len(uris)} live URIs)')
        return False
    st = path.stat()
    tempname = None
    try:
        fd, tempname = tempfile.mkstemp(prefix='.ygg-conf-', dir=str(path.parent))
        with os.fdopen(fd, 'wb') as out:
            out.write(updated.encode('utf-8'))
            out.flush()
            os.fsync(out.fileno())
        os.chown(tempname, st.st_uid, st.st_gid)
        os.chmod(tempname, stat.S_IMODE(st.st_mode))
        check = run('yggdrasil', '-normaliseconf', '-useconffile', tempname)
        if check.returncode:
            raise RuntimeError('Yggdrasil rejected NodeInfo change: ' + (check.stderr or check.stdout).strip())
        backup = None
        if backup_enabled:
            backup = path.with_name(f'{path.name}.bak-{time.strftime("%Y%m%d-%H%M%S")}-{os.getpid()}-pex')
            with open(backup, 'xb') as out:
                os.fchmod(out.fileno(), 0o600)
                out.write(original)
                out.flush()
                os.fsync(out.fileno())
        os.replace(tempname, path)
        tempname = None
        print(f'Updated NodeInfo pex.internet with {len(uris)} Up Internet URIs')
        if backup:
            print(f'Backup: {backup} (mode 0600)')
        return True
    finally:
        if tempname and os.path.exists(tempname):
            os.unlink(tempname)



def restart_yggdrasil():
    print('Restarting Yggdrasil to apply config and published PEX...', flush=True)
    result = run('systemctl', 'restart', 'yggdrasil.service', timeout=60)
    if result.returncode:
        raise RuntimeError('Yggdrasil restart failed: ' + (result.stderr or result.stdout).strip())
    print('Yggdrasil restarted.', flush=True)


INSTALL_PATH = Path('/usr/local/libexec/ygg-peer-pex.py')
SERVICE_PATH = Path('/etc/systemd/system/ygg-peer-pex.service')
TIMER_PATH = Path('/etc/systemd/system/ygg-peer-pex.timer')
SERVICE_TEXT = """[Unit]
Description=Yggdrasil peer exchange full cycle
Wants=yggdrasil.service
After=yggdrasil.service

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /usr/local/libexec/ygg-peer-pex.py --discover --prune-down
TimeoutStartSec=0
"""
TIMER_TEXT = """[Unit]
Description=Run Yggdrasil PEX every 3 hours

[Timer]
OnCalendar=*-*-* 00/3:00:00
Persistent=false
AccuracySec=1min
Unit=ygg-peer-pex.service

[Install]
WantedBy=timers.target
"""


def write_install_file(path, content, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.ygg-pex-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(content)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def systemctl(*args):
    result = run('systemctl', *args, timeout=60)
    if result.returncode:
        raise RuntimeError(f'systemctl {" ".join(args)} failed: ' + (result.stderr or result.stdout).strip())


def configured_service_text(restart=False, config=None):
    path = str(detect_config(config))
    if any(ord(c) < 32 for c in path):
        raise RuntimeError('Invalid config path for systemd')
    quoted = '"' + path.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'
    flags = ' --discover --prune-down' + (' --restart' if restart else '') + ' --config ' + quoted
    return SERVICE_TEXT.replace(' --discover --prune-down\n', flags + '\n')


def install_service(restart=False, config=None):
    config = detect_config(config)
    print(f'Using Yggdrasil config: {config}')
    if not Path('/run/systemd/system').exists():
        raise RuntimeError('systemd system manager not found')
    source = Path(__file__).resolve()
    if not source.is_file():
        raise RuntimeError('Cannot find the script to install')
    # Recognize and upgrade the previous PEX units without clobbering unrelated units.
    for unit, expected in ((SERVICE_PATH, configured_service_text(restart, config)), (TIMER_PATH, TIMER_TEXT)):
        if unit.exists() and unit.read_text() != expected:
            previous = unit.read_text()
            if 'ygg-peer-pex.py' not in previous and 'Yggdrasil PEX' not in previous:
                raise RuntimeError(f'{unit} appears unrelated; refusing to overwrite')
    if INSTALL_PATH.is_symlink() or SERVICE_PATH.is_symlink() or TIMER_PATH.is_symlink():
        raise RuntimeError('Refusing to overwrite symlinked installation files')
    if INSTALL_PATH.exists() and INSTALL_PATH.resolve() != source:
        installed = INSTALL_PATH.read_bytes()
        if b'Discover, persist, prune and exchange working Yggdrasil' not in installed[:250]:
            raise RuntimeError('Install path is occupied by an unrelated script')
        if installed != source.read_bytes():
            print('Updating previously installed script in /usr/local/libexec/', flush=True)
    write_install_file(INSTALL_PATH, source.read_bytes(), 0o755)
    write_install_file(SERVICE_PATH, configured_service_text(restart, config).encode(), 0o644)
    write_install_file(TIMER_PATH, TIMER_TEXT.encode(), 0o644)
    systemctl('daemon-reload')
    # Never wait for a long-running PEX scan when activating a timer.
    systemctl('enable', 'ygg-peer-pex.timer')
    systemctl('start', '--no-block', 'ygg-peer-pex.timer')
    print('Installed /usr/local/libexec/ygg-peer-pex.py and systemd timer (every 3 hours).')
    print('Check: systemctl status ygg-peer-pex.timer')
    print('Logs:  journalctl -u ygg-peer-pex.service -n 60 --no-pager')
    print('Manual: sudo systemctl start ygg-peer-pex.service')
    print('Service runs --discover --prune-down' + (' --restart' if restart else '') + '.')


def uninstall_service():
    if TIMER_PATH.exists() or SERVICE_PATH.exists():
        result = run('systemctl', 'disable', '--now', 'ygg-peer-pex.timer', timeout=60)
        if result.returncode:
            print('Warning: could not disable timer:', (result.stderr or result.stdout).strip(), flush=True)
        # A scan may take a while; stop the unit without blocking uninstall.
        result = run('systemctl', 'stop', '--no-block', 'ygg-peer-pex.service', timeout=20)
        if result.returncode:
            print('Warning: could not stop service:', (result.stderr or result.stdout).strip(), flush=True)
    # Only remove our own units. Never touch Yggdrasil config or its peers.
    for path, expected in ((SERVICE_PATH, SERVICE_TEXT), (TIMER_PATH, TIMER_TEXT)):
        if path.exists() and path.read_text() != expected:
            previous = path.read_text()
            if 'ygg-peer-pex.py' not in previous and 'Yggdrasil PEX' not in previous:
                raise RuntimeError(f'{path} is not our PEX unit; refusing to delete')
    if INSTALL_PATH.is_symlink():
        raise RuntimeError('Installed script is symlinked; refusing to delete')
    if INSTALL_PATH.exists() and b'Discover, persist, prune and exchange working Yggdrasil' not in INSTALL_PATH.read_bytes()[:250]:
        raise RuntimeError('Installed script does not look like our PEX; refusing to delete')
    for path in (TIMER_PATH, SERVICE_PATH, INSTALL_PATH):
        if path.exists():
            path.unlink()
    systemctl('daemon-reload')
    print('Uninstalled timer and script. Yggdrasil config was not changed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('uri', nargs='?', help='URI, install or uninstall')
    parser.add_argument('--discover', action='store_true', help='Find peers via getTree -> NodeInfo')
    parser.add_argument('--publish-only', action='store_true', help='Only write live Up peer URIs into NodeInfo PEX')
    parser.add_argument('--no-publish', action='store_true', help='Do not update PEX after discover/manual add')
    parser.add_argument('--prune-down', action='store_true', help='Remove confirmed Down URIs from config; never remove all')
    parser.add_argument('--max-new', type=int, default=None, help='Optional limit on new peers saved (default: unlimited)')
    parser.add_argument('--max-nodes', type=int, default=None, help='Optional limit on nodes queried (default: all getTree nodes)')
    parser.add_argument('--config', type=Path, default=None, help='Config path (default: auto-detect)')
    parser.add_argument('--backup', action='store_true', help='Create timestamped backup before config edits (off by default)')
    parser.add_argument('--timeout', type=int, default=12, help='Seconds to wait for a candidate to become Up')
    parser.add_argument('--restart', action='store_true', help='Restart Yggdrasil after cycle only if config was modified')
    parser.add_argument('--restart-on-publish', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.uri in ('install', 'uninstall'):
        if os.geteuid() != 0:
            parser.error('Run install/uninstall with sudo')
        if args.discover or args.publish_only or args.prune_down:
            parser.error('install/uninstall cannot be mixed with discovery flags')
        try:
            if args.uri == 'install':
                install_service(restart=args.restart or args.restart_on_publish, config=args.config)
            else:
                uninstall_service()
            return 0
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            print('ERROR:', exc, file=sys.stderr)
            return 1
    if sum([bool(args.uri), args.discover, args.publish_only]) == 0 and not args.prune_down:
        parser.error('Specify URI, --discover, --publish-only or --prune-down')
    if sum([bool(args.uri), args.discover, args.publish_only]) > 1:
        parser.error('Specify at most one of URI, --discover, --publish-only')
    if args.uri and not valid_uri(args.uri):
        parser.error('Invalid URI (supported: tcp, tls, quic with host and port)')
    if (args.max_new is not None and args.max_new < 1) or (args.max_nodes is not None and args.max_nodes < 1):
        parser.error('--max-new and --max-nodes must be positive when specified')
    if os.geteuid() != 0:
        parser.error('Run with sudo to access socket and modify config')
    try:
        args.config = detect_config(args.config)
    except (RuntimeError, OSError) as exc:
        parser.error(str(exc))
    try:
        insert_peer(args.config.read_text('utf-8'), 'tls://example.com:1234')
        nodeinfo_section(args.config.read_text('utf-8'))
    except (ValueError, OSError) as exc:
        parser.error(f'Config layout unsupported: {exc}')

    with open('/run/lock/ygg-peer-add.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            dns_cache = {}
            changed = False
            if args.uri:
                if not is_public_transport(args.uri, dns_cache):
                    print('Skipping non-public or unresolvable:', args.uri)
                    return 1
                if args.uri in configured_uris(args.config.read_text('utf-8')):
                    state = state_for(args.uri)
                    if state == 'Up':
                        print('Already configured and Up:', args.uri)
                    else:
                        print('Already configured; checking runtime...')
                        if state is None:
                            r = run('yggdrasilctl', 'addPeer', f'uri={args.uri}')
                            if r.returncode:
                                raise RuntimeError('addPeer failed: ' + (r.stderr or r.stdout).strip())
                        deadline = time.monotonic() + args.timeout
                        while time.monotonic() < deadline:
                            if state_for(args.uri) == 'Up':
                                print('Peer Up and already persisted')
                                break
                            time.sleep(2)
                        else:
                            print('Peer not Up; config unchanged')
                else:
                    changed = add_if_working(args.uri, args.config, args.timeout, dns_cache, args.backup)
            elif args.discover:
                saved = 0
                for uri in discover_uris(args.max_nodes):
                    if add_if_working(uri, args.config, args.timeout, dns_cache, args.backup):
                        saved += 1
                        changed = True
                        if args.max_new is not None and saved >= args.max_new:
                            break
                print(f'Discovery done: {saved} new working URIs saved')
            if args.prune_down:
                changed = prune_down(args.config, args.backup) or changed
            if not args.no_publish:
                changed = publish_active(args.config, args.backup) or changed
            if changed:
                if args.restart or args.restart_on_publish:
                    restart_yggdrasil()
                else:
                    print('Config changed on disk; restart Yggdrasil when convenient to apply changes.')
            return 0
        except (RuntimeError, ValueError, OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
            print('ERROR:', exc, file=sys.stderr)
            return 1


if __name__ == '__main__':
    sys.exit(main())
