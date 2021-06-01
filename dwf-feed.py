#!/usr/bin/env python3
import ujson
import gzip
import sys
import time

from pathlib import Path


def collect_cve_item(file):
    print(f'I: Loading {file}')

    with open(file) as f:
        data = f.read()

        try:
            json_data = ujson.loads(data)
            return json_data
        except Exception as e:
            print(f'E: Got {e} while processing {file}')
            return None


def collect_json_paths(dir):
    print(f'I: Iterating over {dir}')

    return [str(x) for x in dir.iterdir() if x.is_file()]


def iterate_collection(dir):
    print(f'I: Iterating over {dir}')

    json_paths = [collect_json_paths(x) for x in dir.iterdir()]
    json_paths = [y for x in json_paths for y in x]

    cve_items = [collect_cve_item(x) for x in json_paths]
    cve_items = [x for x in cve_items if x]

    obj = {
        'CVE_data_type': 'CVE',
        'CVE_data_format': 'MITRE',
        'CVE_data_version': '4.0',
        'CVE_data_numberOfCVEs': len(cve_items),
        'CVE_data_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'CVE_items': cve_items,
    }

    p = Path('wwwroot/feeds') / f'dwfcve-{dir.parts[-1]}.json.gz'
    print(f'I: Writing {p}')

    payload = ujson.dumps(obj).encode('utf-8')
    with gzip.open(p, 'wb', compresslevel=9) as f:
        f.write(payload)


def iterate_directory(dir):
    print(f'I: Iterating over {dir}')

    p = Path(dir)
    if not p.is_dir():
        print(f'E: {dir} is not a directory')
        return

    [iterate_collection(x) for x in p.iterdir() if x.is_dir() and not '.git' in str(x)]


def usage():
    print('usage: python3 dwf-feed.py ../path/to/dwflist')
    exit()


def main():
    if len(sys.argv) < 2:
        usage()

    iterate_directory(sys.argv[1])


if __name__ == '__main__':
    main()
