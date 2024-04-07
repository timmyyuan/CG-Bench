#!/usr/bin/env python3
import os
import json

def get_project(callsite):
    projects = [
        'redis',
        'zfs',
        'wrk',
        'gcc',
        'ffmpeg',
        'curl',
        'openssh'
    ]

    for p in projects:
        if p in callsite:
            return p
        
    print('Unknown callsite:', callsite)
    return 'unknown'

history = {}

def parse(lines, kind):
    results = {}
    next_is_callsite = False
    next_is_code = False
    codes = []
    for line in lines:
        if next_is_callsite:
            if line.startswith('*'):
                callsite = line.strip()[1:-1]
                project = get_project(callsite)
                if callsite in history:
                    print(callsite)

                history[callsite] = True

                if project not in results:
                    results[project] = {}

                results[project].update({
                    callsite: {
                        "callsite" : "",
                        "type": kind,
                        "chain_summary": [],
                        "callees": {
                        }
                    }
                })
            next_is_callsite = False

        if line.startswith('```'):
            if len(codes) > 0:
                results[project][callsite]['chain_summary'].append({
                    'source_code': codes,
                    'parent': "",
                })
            codes = []
            next_is_code = False

        if next_is_code:
            codes.append(line[:-1])

        if line.startswith('## Callsite'):
            next_is_callsite = True
        
        if line.startswith('fnptr: '):
            fnptr = line.strip().split(' ')[-1][1:-1]
            results[project][callsite]['callsite'] = fnptr

        if line.startswith('targets: '):
            targets = line.strip().split(': ')[-1].split(', ')
            results[project][callsite]['callees']['targets'] = {t:"" for t in targets}

        if line.startswith('```c'):
            next_is_code = True
    
    return results


def main():
    results = {}
    for dirpath, dirs, files in os.walk(os.curdir):
        fpaths = [os.path.join(dirpath, f) for f in files if f.endswith('.md')]
        for fpath in fpaths:
            with open(fpath, 'r') as fp:
                data = parse([l for l in fp.readlines() if l.strip()], os.path.basename(fpath)[:-3])
            print(fpath, len(data))

            if len(results) == 0:
                results.update(data)

            for k in data:
                if k in results:
                    results[k].update(data[k])
                else:
                    results[k] = data[k]
    
    with open(os.path.join(os.curdir, 'cgbench.json'), 'w') as fp:
        fp.write(json.dumps(results, indent=4))

if __name__ == '__main__':
    main()
