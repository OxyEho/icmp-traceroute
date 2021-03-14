import argparse

from traceroute import Traceroute
from icmp import IcmpPack


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('host', type=str)
    args = arg_parser.parse_args()
    traceroute = Traceroute(args.host)
    trace_result = traceroute.make_trace()
    for count, el in enumerate(trace_result, start=1):
        print(f'{count}. {el}')
    # pack = IcmpPack(8, 0)
    # print(len(pack.pack_icmp()))
