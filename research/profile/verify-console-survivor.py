#!/usr/bin/env python3
"""Offline AMD-console/NVIDIA-driver ownership check for one observed machine.

GPL-2.0-only. Reads a completed passive diagnostic; never authorizes a driver
stop, GPU reset, unlock, firmware mutation or a safe recovery claim.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path

PCI = '4cf5b200-68b8-4ca5-9eec-b23e3f50029a'
PATH = '09576e91-6d3f-11d2-8e39-00a0c969723b'
GOP = '9042a9de-23dc-4a38-96fb-7aded080516a'
TEXT = '387477c2-69c7-11d2-8e39-00a0c969723b'
EDID = '1c0c34f6-d380-41fa-a049-8ad06c1a66aa'
# Machine-specific observations, NOT a generic hardware support list.
EXPECTED = {
    '0000:01:00.0': (0x268410de, 0x88e61043, 0x030000a1, 0x7000b, 'nvgop-ad1xx', 0x278e0, 0x6ec),
    '0000:04:00.0': (0x220a10de, 0xb61219da, 0x030000a1, 0x60010, 'nvgop-ga1xx', 0x26ae0, 0x678),
    '0000:0f:00.0': (0x13c01002, 0x7e561462, 0x030000cb, 0x30808, None, 0x144a0, None),
}
AMD = '0000:0f:00.0'
TARGETS = ('0000:04:00.0', '0000:01:00.0')


class Refused(ValueError):
    pass


def only(items, description):
    if len(items) != 1:
        raise Refused(f'exactly one {description} required')
    return items[0]


def location(block):
    line = only(re.findall(r'^pci location-status=([^\n]+)$', block['raw'], re.M), 'PCI location')
    m = re.fullmatch(r'0x0+ segment=0x([0-9a-f]+) bus=0x([0-9a-f]+) device=0x([0-9a-f]+) function=0x([0-9a-f]+)', line)
    if m is None:
        raise Refused('PCI location status not successful')
    seg, bus, dev, fun = (int(x, 16) for x in m.groups())
    if seg > 0xffff or bus > 255 or dev > 31 or fun > 7:
        raise Refused('PCI location outside valid range')
    return f'{seg:04x}:{bus:02x}:{dev:02x}.{fun}'


def paths(raw, prefix='path-node raw='):
    nodes = re.findall(r'^' + re.escape(prefix) + r'([0-9a-f]+)$', raw, re.M)
    if not nodes or any(len(node) % 2 for node in nodes):
        raise Refused('missing or malformed display path')
    data = b''.join(bytes.fromhex(node) for node in nodes)
    at = 0
    for i, node in enumerate(nodes):
        chunk = bytes.fromhex(node)
        if len(chunk) < 4 or int.from_bytes(chunk[2:4], 'little') != len(chunk):
            raise Refused('display path node has invalid length')
        if chunk[:4] == b'\x7f\xff\x04\x00' and i != len(nodes)-1:
            raise Refused('display path has trailing nodes')
        at += len(chunk)
    if nodes[-1] != '7fff0400' or at != len(data):
        raise Refused('display path lacks end-entire node')
    return data


def inventory(source):
    starts = list(re.finditer(r'^probe-inventory-v2 begin$', source, re.M))
    ends = list(re.finditer(r'^probe-inventory-v2 end displays=0x([0-9a-f]+) failures=0x([0-9a-f]+) complete=([01])$', source, re.M))
    rows = list(re.finditer(r'^probe-display-v2 ([^\n]+)$', source, re.M))
    if (len(starts) != 1 or len(ends) != 1 or
            len(re.findall(r'^probe-inventory-v2 end.*$', source, re.M)) != 1 or
            tuple(int(x, 16) for x in ends[0].groups()) != (3, 0, 1) or len(rows) != 3 or
            any(not starts[0].end() < row.start() < ends[0].start() for row in rows)):
        raise Refused('incomplete or unexpected display inventory')
    observed = {}
    for row in rows:
        fields = [pair.split('=', 1) for pair in row[1].split()]
        if any(len(pair) != 2 for pair in fields):
            raise Refused('malformed inventory record')
        record = dict(fields)
        if len(record) != len(fields):
            raise Refused('duplicate inventory field')
        try:
            bdf = f"{int(record['seg'],16):04x}:{int(record['bus'],16):02x}:{int(record['dev'],16):02x}.{int(record['fun'],16)}"
            values = tuple(int(record[k], 16) for k in ('id', 'subsystem', 'class'))
            good = (record['stable'] == '1' and record['duplicate'] == '0' and
                    all(int(record[k], 16) == 0 for k in ('loc-status', 'config-status', 'repeat-status',
                                                        'attrs-status', 'supported-status', 'path-status')))
        except (KeyError, ValueError) as exc:
            raise Refused('malformed inventory identity or status') from exc
        if bdf not in EXPECTED or values != EXPECTED[bdf][:3] or not good or bdf in observed:
            raise Refused('inventory identity or observation drift')
        observed[bdf] = values
    if set(observed) != set(EXPECTED):
        raise Refused('missing or additional display controller')
    return observed


def bound_driver(graph, handle, config, bdf):
    opens = [edge for edge in graph[handle]['edges'] if edge[0] == PCI and edge[3] == 16]
    protocol, agent, controller, attrs, count = only(opens, f'{bdf} PCI driver owner')
    if controller != handle or count != 1 or agent not in graph:
        raise Refused(f'{bdf} PCI driver owner invalid')
    record = only(re.findall(r'^driver image=0x([0-9a-f]+) binding=0x([0-9a-f]+) version=0x([0-9a-f]+) stop-address=0x([0-9a-f]+)$', graph[agent]['raw'], re.M), f'{bdf} driver binding')
    image, binding, version, stop = (int(x, 16) for x in record)
    if binding != agent or version != config[3]:
        raise Refused(f'{bdf} driver binding version/identity mismatch')
    images = re.findall(r'^image parent=0x[0-9a-f]+ device=0x([0-9a-f]+) base=0x([0-9a-f]+) size=0x([0-9a-f]+) code-type=0x([0-9a-f]+)$', graph[image]['raw'], re.M) if image in graph else []
    device, base, size, code = (int(x, 16) for x in only(images, f'{bdf} driver image'))
    if device != handle or size != config[5] or code != 3 or not base <= stop < base+size:
        raise Refused(f'{bdf} driver image differs from captured metadata')
    if config[6] is not None and stop-base != config[6]:
        raise Refused(f'{bdf} driver stop offset differs from captured metadata')
    if config[4] is not None:
        encoded = only(re.findall(r'^image-file-path-node raw=([0-9a-f]+)$', graph[image]['raw'], re.M), f'{bdf} driver image name')
        data = bytes.fromhex(encoded)
        if len(data) < 6 or data[:2] != b'\x04\x04' or int.from_bytes(data[2:4], 'little') != len(data):
            raise Refused(f'{bdf} driver image path not a file node')
        try:
            label = data[4:].decode('utf-16-le').rstrip('\x00')
        except UnicodeDecodeError as exc:
            raise Refused(f'{bdf} driver image name invalid') from exc
        if label != config[4]:
            raise Refused(f'{bdf} driver image name mismatch')
    return agent


def inspect(source, parse_handles):
    inventory(source)
    if re.findall(r'^gops=.*$', source, re.M) != ['gops=0001']:
        raise Refused('expected exactly one firmware GOP in capture')
    if re.findall(r'^probe targets=.*$', source, re.M) != ['probe targets=0002 cfg-incomplete=0000']:
        raise Refused('unexpected probe target or failed PCI config read')
    try:
        graph = parse_handles(source)
    except (ValueError, KeyError, TypeError) as exc:
        raise Refused('diagnostic ownership graph incomplete') from exc
    devices = {}
    for handle, block in graph.items():
        if PCI not in block['protocols']:
            continue
        cfg_lines = re.findall(r'^pci config-dwords=([^\n]+)$', block['raw'], re.M)
        if len(cfg_lines) != 1:
            raise Refused('PCI controller missing configuration')
        values = [int(x, 16) for x in cfg_lines[0].split()]
        if len(values) != 16:
            raise Refused('malformed graph PCI configuration')
        if values[2] >> 24 == 3:
            bdf = location(block)
            if bdf not in EXPECTED or values[0] != EXPECTED[bdf][0] or values[11] != EXPECTED[bdf][1] or values[2] != EXPECTED[bdf][2] or bdf in devices:
                raise Refused('PCI ownership graph differs from display inventory')
            devices[bdf] = handle
    if set(devices) != set(EXPECTED):
        raise Refused('graph display controller set is incomplete')
    owners = {bdf: bound_driver(graph, handle, EXPECTED[bdf], bdf) for bdf, handle in devices.items()}
    if len(set(owners.values())) != 3:
        raise Refused('GPU driver binding handle reused across display controllers')
    for bdf in TARGETS:
        h = devices[bdf]
        if any(edge[3] == 8 for edge in graph[h]['edges']):
            raise Refused(f'{bdf} has active child controller relation')
    gops = [handle for handle, block in graph.items() if GOP in block['protocols']]
    gop = only(gops, 'AMD-only GOP')
    if GOP not in graph[gop]['protocols'] or PATH not in graph[gop]['protocols']:
        raise Refused('AMD GOP protocols incomplete')
    gpupath = paths(graph[gop]['raw'])
    pcipath = paths(graph[devices[AMD]]['raw'])
    if not gpupath.startswith(pcipath[:-4]) or gpupath == pcipath:
        raise Refused('GOP path does not descend from AMD PCI route')
    amd_edges = graph[devices[AMD]]['edges']
    if not any(edge[0] == PCI and edge[1] == owners[AMD] and edge[2] == gop and edge[3:] == (8, 1) for edge in amd_edges):
        raise Refused('AMD driver does not own the GOP child')
    for name in ('ConOut', 'ConOutDev', 'ErrOut', 'ErrOutDev'):
        sections = re.findall(r'^variable name=' + name + r' initial-status=([^\n]+)\n(.*?)(?=^variable name=|^probe-inventory-v2 begin|\Z)', source, re.M | re.S)
        status, section = only(sections, name + ' variable')
        logged = only(re.findall(r'^variable-status=0x([0-9a-f]+) attrs=0x([0-9a-f]+) bytes=0x([0-9a-f]+)$', section, re.M), name + ' variable status')
        if int(logged[0], 16) or int(logged[2], 16) != len(gpupath) or paths(section) != gpupath:
            raise Refused(name + ' does not exclusively route to AMD GOP')
    con = only(re.findall(r'^console out=0x([0-9a-f]+) error=0x([0-9a-f]+) input=0x([0-9a-f]+)$', source, re.M), 'console handles')
    console = int(con[0], 16)
    if not console or con[1] != con[0] or console not in graph or TEXT not in graph[console]['protocols']:
        raise Refused('active firmware text console incomplete')
    # Preserve AMD-backed graphics/text/EDID consumers, including the shared
    # virtual text console; the remaining NVIDIA bindings may not own them.
    consumers = {}
    for protocol in (GOP, TEXT, EDID):
        edges = [edge for edge in graph[gop]['edges'] if edge[0] == protocol and edge[3] == 16]
        consumer = only(edges, 'AMD ' + protocol + ' consumer')
        if consumer[2] != gop or consumer[4] != 1 or consumer[1] not in graph or consumer[1] in owners.values():
            raise Refused('AMD console consumer ownership invalid')
        consumers[protocol] = consumer[1]
    if not any(e[0] == TEXT and e[1] == consumers[TEXT] and e[2] == console and e[3:] == (8, 1) for e in graph[gop]['edges']):
        raise Refused('AMD GOP lacks virtual text-console child')
    return {
        'schema': 'offline-amd-console-observation/1',
        'status': 'observed_amd_only_console',
        'devices': [{'bdf': bdf, 'pci_id': f'{EXPECTED[bdf][0] & 0xffff:04x}:{EXPECTED[bdf][0] >> 16:04x}',
                     'role': 'surviving_display' if bdf == AMD else 'bound_without_display_child'} for bdf in (AMD, *TARGETS)],
        'gop_count': 1,
        'protected_console_protocols': ['graphics_output', 'simple_text_output', 'edid_discovered'],
        'can_detach': False, 'can_unlock': False,
        'vendor_stop_code_verified': False, 'recovery_after_release_verified': False,
    }, graph, devices, owners


def check_model_transition(before, after, target, devices, owners):
    """Check exactly one modeled PCI owner-open removal. NOT a Stop() simulator."""
    if target not in TARGETS or set(before) != set(after):
        raise Refused('model target invalid or handles changed')
    h = devices[target]
    expected = (PCI, owners[target], h, 16, 1)
    for handle, block in before.items():
        following = after[handle]
        if following['protocols'] != block['protocols'] or following['raw'] != block['raw']:
            raise Refused('model changed protected metadata or protocol set')
        old, new = set(block['edges']), set(following['edges'])
        if len(old) != len(block['edges']) or len(new) != len(following['edges']):
            raise Refused('duplicate modeled ownership relation')
        if handle == h:
            if expected not in old or old - new != {expected} or new - old:
                raise Refused('model target owner did not release exactly once')
        elif old != new:
            raise Refused('model modified the other GPU or shared console')
    return {'status': 'modeled_single_owner_open_removal', 'hardware_released': False,
            'can_detach': False, 'can_unlock': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('diagnostic', type=Path)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    if not args.diagnostic.is_file() or args.diagnostic.is_symlink() or args.diagnostic.stat().st_size > 8*1024*1024:
        p.error('invalid, symlinked or oversized diagnostic file')
    spec = importlib.util.spec_from_file_location('gu_capture_graph', Path(__file__).with_name('capture_graph.py'))
    if not spec or not spec.loader:
        p.error('capture_graph.py unavailable')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        result, _, _, _ = inspect(args.diagnostic.read_text(encoding='utf-8'), module.parse_handles)
    except (ValueError, UnicodeDecodeError) as exc:
        p.error(f'observation refused: {exc}')
    payload = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(payload, encoding='utf-8')
    else:
        print(payload, end='')


if __name__ == '__main__':
    main()
