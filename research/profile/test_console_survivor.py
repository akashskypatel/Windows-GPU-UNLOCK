"""Synthetic ownership graph regressions for the offline AMD-console verifier."""
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('console_survivor', HERE / 'verify-console-survivor.py')
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
parser_spec = importlib.util.spec_from_file_location('console_graph', HERE / 'capture_graph.py')
graph_parser = importlib.util.module_from_spec(parser_spec)
parser_spec.loader.exec_module(graph_parser)

AMD_PATH = ['02010c00d041030a00000000', '010106000108', '010106000000',
            '0203080000030180', '7fff0400']
AMD_PCI_PATH = AMD_PATH[:3] + ['7fff0400']


def nodes(parts):
    return ''.join('path-node raw=' + p + '\n' for p in parts)


def fixture():
    rows = ['gpu-console-graph-v1 observational-only; no-detach no-unlock no-nvram-write',
            'console out=0x5 error=0x5 input=0x5']
    for name in ('ConOut', 'ConOutDev', 'ErrOut', 'ErrOutDev'):
        rows.append(f'variable name={name} initial-status=0x8000000000000005 bytes=0x24')
        rows.append('variable-status=0x0000000000000000 attrs=0x0000000000000007 bytes=0x0000000000000024')
        rows.extend('path-node raw=' + x for x in AMD_PATH)
    rows.append('probe-inventory-v2 begin')
    for bdf, config in v.EXPECTED.items():
        seg, rest = bdf.split(':', 1)
        bus, df = rest.split(':')
        dev, fun = df.split('.')
        ordered = ['seg','bus','dev','fun','id','class','subsystem','command','loc-status','config-status',
                   'repeat-status','attrs-status','attrs','supported-status','supported','path-status','stable','duplicate']
        d = {x:'0x0' for x in ordered}
        d.update(seg=f'0x{int(seg,16):04x}',bus=f'0x{int(bus,16):02x}',dev=f'0x{int(dev,16):02x}',
                 fun=f'0x{int(fun):02x}', id=f'0x{config[0]:08x}',**{'class':f'0x{config[2]:08x}'},
                 subsystem=f'0x{config[1]:08x}',stable='1',duplicate='0')
        rows.append('probe-display-v2 '+' '.join(f'{k}={d[k]}' for k in ordered))
    rows.append('probe-inventory-v2 end displays=0x3 failures=0x0 complete=1')
    rows.extend(['probe targets=0002 cfg-incomplete=0000', 'gops=0001'])

    def add(h, chunks):
        rows.append(f'handle id=0x{h:x}')
        for guid, edges, extras in chunks:
            rows.append('protocol guid=' + guid)
            rows.append(f'opens status=0x0 count=0x{len(edges):x}')
            for agent, controller, attrs, count in edges:
                rows.append(f'open agent=0x{agent:x} controller=0x{controller:x} attributes=0x{attrs:x} count=0x{count:x}')
            rows.extend(extras)

    # Controller: PCI I/O, device-path, exact 16-word configuration and BDF.
    for h, driver, bdf in ((1,6,'0000:01:00.0'),(2,7,'0000:04:00.0'),(3,8,'0000:0f:00.0')):
        config = v.EXPECTED[bdf]
        cfg = [0]*16
        cfg[0],cfg[2],cfg[11] = config[0],config[2],config[1]
        bus = int(bdf[5:7],16)
        props = [f'pci location-status=0x0 segment=0x0 bus=0x{bus:x} device=0x0 function=0x0',
                 'pci config-status=0x0000000000000000',
                 'pci config-dwords='+' '.join(f'{n:08x}' for n in cfg)]
        add(h, [(v.PCI, [(driver,h,16,1)] + ([(driver,4,8,1)] if h == 3 else []),props),
                (v.PATH, [],nodes(AMD_PCI_PATH).splitlines() if h==3 else [])])
    add(4, [(v.PATH, [],nodes(AMD_PATH).splitlines()),
            (v.GOP, [(9,4,16,1)],[]),
            (v.TEXT, [(10,4,16,1),(10,5,8,1)],[]),
            (v.EDID, [(11,4,16,1)],[])])
    add(5, [(v.TEXT,[],[])])
    for h, name, bdf in ((6,'nvgop-ad1xx','0000:01:00.0'), (7,'nvgop-ga1xx','0000:04:00.0'), (8,None,'0000:0f:00.0')):
        cfg=v.EXPECTED[bdf]
        base=0x100000*h
        stop_offset = cfg[6] if cfg[6] is not None else 0x1058
        raw = [f'driver image=0x{h:x} binding=0x{h:x} version=0x{cfg[3]:x} stop-address=0x{base+stop_offset:x}',
               f'image parent=0x0 device=0x{(1 if h==6 else 2 if h==7 else 3):x} base=0x{base:x} size=0x{cfg[5]:x} code-type=0x3']
        if name:
            encoded=(bytes([4,4])+(4+(len(name)+1)*2).to_bytes(2,'little')+(name+'\x00').encode('utf-16-le')).hex()
            raw.append('image-file-path-node raw='+encoded)
        add(h, [('18a031ab-b443-4d1a-a5c0-0c09261e9f71',[],raw)])
    for h in (9,10,11):
        add(h, [('18a031ab-b443-4d1a-a5c0-0c09261e9f71',[],[])])
    rows.extend(['handles status=0x0000000000000000 count=0x000000000000000b',
                 'capture-complete=1', 'diagnostic-result status=0x0000000000000000'])
    # Handle count marker precedes the handle blocks in the actual diagnostic.
    row = rows.pop(-3)
    insert = next(i for i,line in enumerate(rows) if line.startswith('handle id='))
    rows.insert(insert,row)
    return '\n'.join(rows)+'\n'


class SurvivorTests(unittest.TestCase):
    def test_complete_amd_survivor_is_observation_only(self):
        result, graph, devices, owners = v.inspect(fixture(),graph_parser.parse_handles)
        self.assertEqual(result['status'],'observed_amd_only_console')
        self.assertEqual(result['gop_count'],1)
        self.assertFalse(result['can_detach'])
        self.assertFalse(result['can_unlock'])
        self.assertEqual(len(devices),3)
        self.assertEqual(len(set(owners.values())),3)

    def test_no_nvidia_display_is_not_same_as_missing_nvidia_driver(self):
        sample=fixture().replace('open agent=0x7 controller=0x2 attributes=0x10 count=0x1','open agent=0x7 controller=0x2 attributes=0x2 count=0x1')
        with self.assertRaises(v.Refused):v.inspect(sample,graph_parser.parse_handles)

    def test_refuse_console_variable_reroute(self):
        sample=fixture().replace('0203080000030180','0203080080030180',1)
        with self.assertRaises(v.Refused):v.inspect(sample,graph_parser.parse_handles)

    def test_refuse_wrong_driver_image_identity(self):
        # The encoded UTF-16 path, not source labels, owns the firmware name.
        sample=fixture().replace('6e00760067006f0070002d0061006400310078007800', '6e00760067006f0070002d0067006100310078007800')
        with self.assertRaises(v.Refused):v.inspect(sample,graph_parser.parse_handles)

    def test_refuse_driver_version_or_stop_offset_change(self):
        good=fixture()
        for bad in (good.replace('version=0x60010','version=0x60011'),
                    good.replace('stop-address=0x700678','stop-address=0x700679')):
            with self.subTest(bad=bad[-100:]),self.assertRaises(v.Refused):
                v.inspect(bad,graph_parser.parse_handles)

    def test_refuse_partial_graph_and_missing_amd_gop(self):
        good=fixture()
        for bad in (good.replace('capture-complete=1','capture-complete=0'),
                    good.replace('opens status=0x0 count=0x1','opens status=0x0 count=0x2',1),
                    good.replace('protocol guid='+v.GOP,'protocol guid=00000000-0000-0000-0000-000000000000')):
            with self.subTest(bad=bad[-80:]),self.assertRaises(v.Refused):
                v.inspect(bad,graph_parser.parse_handles)

    def test_refuse_nvidia_child_even_if_amd_console_still_works(self):
        good=fixture()
        bad=good.replace('open agent=0x6 controller=0x1 attributes=0x10 count=0x1',
                         'open agent=0x6 controller=0x1 attributes=0x8 count=0x1')
        with self.assertRaises(v.Refused):v.inspect(bad,graph_parser.parse_handles)

    def test_one_edge_model_requires_every_other_relationship_unchanged(self):
        result, graph, devices, owners=v.inspect(fixture(),graph_parser.parse_handles)
        target=v.TARGETS[0]
        after=copy.deepcopy(graph)
        owner=(v.PCI,owners[target],devices[target],16,1)
        after[devices[target]]['edges'].remove(owner)
        modeled=v.check_model_transition(graph,after,target,devices,owners)
        self.assertEqual(modeled['status'],'modeled_single_owner_open_removal')
        self.assertFalse(modeled['hardware_released'])
        with self.assertRaises(v.Refused):v.check_model_transition(graph,graph,target,devices,owners)
        mutations=[]
        extra=copy.deepcopy(after)
        extra[devices[v.AMD]]['edges'].pop()
        mutations.append(extra)
        extra=copy.deepcopy(after)
        extra[devices[v.TARGETS[1]]]['edges'].pop()
        mutations.append(extra)
        extra=copy.deepcopy(after)
        extra[4]['edges'].pop()
        mutations.append(extra)
        extra=copy.deepcopy(after)
        extra[4]['protocols'].remove(v.GOP)
        mutations.append(extra)
        for index, wrong in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(v.Refused):
                v.check_model_transition(graph,wrong,target,devices,owners)


if __name__ == '__main__':
    unittest.main()
