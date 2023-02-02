import http.client
import argparse
import operator
import sys
import threading
import time
from functools import reduce

from tqdm.auto import tqdm

parser = argparse.ArgumentParser(
    prog="intruder",
    description="Burp-like intruder that lets you send requests with fuzzed headers/body/url",
    epilog="Example: intruder -w wordlist.txt -r request.txt -h google.com",
    add_help=False
)
parser.add_argument("--help", action="help", help="Show this message")
parser.add_argument("-w", metavar="<filename or list>", help="Wordlist file or comma separated list e.g.: USER:path/to/wordlist1.txt,PASS:path/to/wordlist2.txt")
parser.add_argument("-r", metavar="<filename>", help="Request file")
parser.add_argument("-h", metavar="<host>", help="Host e.g. google.com")
parser.add_argument("-d", metavar="<float>", help="Delay between requests in seconds e.g. 0.1", default="0")
parser.add_argument("-t", metavar="<int>", help="Number of threads", default="40")
parser.add_argument("-p", metavar="<protocol>", help="Protocol (http or https)", default="http")
parser.add_argument("-c", help="Color output", action="store_true")

bar = None
args = parser.parse_args()
if "," in args.w:
    fuzz_dict = {fuzz[0]: fuzz[1] for fuzz in [fuzz.split(":", 1) for fuzz in args.w.split(",")]}
else:
    fuzz_dict = {"FUZZ": args.w}
request_file = args.r
host = args.h
num_threads = int(args.t)
time_delay = float(args.d)
protocol = args.p
color_output = args.c
lock = threading.Lock()
print_lock = threading.Lock()
if protocol == "http":
    response_class = http.client.HTTPResponse
    connection_class = http.client.HTTPConnection
elif protocol == "https":
    response_class = http.client.HTTPResponse
    connection_class = http.client.HTTPSConnection
else:
    print(f"Unrecognized protocol: '{protocol}'")
    sys.exit(1)


def c(status_code):
    if not color_output:
        return status_code
    code_prefix = int(status_code) // 100
    if code_prefix == 2:
        return "\033[0;34m" + status_code + "\033[0m"
    if code_prefix == 3:
        return "\033[0;32m" + status_code + "\033[0m"
    if code_prefix == 4:
        return "\033[1;33m" + status_code + "\033[0m"
    if code_prefix == 5:
        return "\033[0;31m" + status_code + "\033[0m"
    return status_code


def get_request():
    with open(request_file, "r") as f:
        content = "\r\n".join([line.removesuffix('\r\n').removesuffix('\n') for line in f.readlines()])
        if not content.endswith("\r\n\r\n"):
            if content.endswith("\r\n"):
                content = content + "\r\n"
            else:
                content = content + "\r\n\r\n"
        return content


def get_wordlist_lines():
    global bar
    total = reduce(operator.mul, [len(open(filename, "r").readlines()) for filename in fuzz_dict.values()])
    bar = tqdm(
        total=total,
        unit=" requests",
        ncols=23 + 20 * len(fuzz_dict.keys()),
        initial=0,
        colour="green" if color_output else None
    )
    files = [open(filename, "r") for filename in fuzz_dict.values()]
    lines = [f.readline() for f in files]
    yield lines
    while True:
        idx = len(lines) - 1
        while lines[idx] == "" and idx > 0:
            files[idx].close()
            files[idx] = open(list(fuzz_dict.values())[idx], "r")
            lines[idx] = files[idx].readline()
            lines[idx - 1] = files[idx - 1].readline()
            idx -= 1
        if lines[idx] == "" and idx == 0:
            break
        yield lines
        lines[-1] = files[-1].readline()


wordlist_lines = get_wordlist_lines()
request_str = get_request()


def intruder_runner():
    while True:
        lock.acquire()
        try:
            lines = [line.rstrip() for line in next(wordlist_lines)]
        except StopIteration:
            lock.release()
            break
        if time_delay > 0:
            time.sleep(time_delay)
        lock.release()
        request_str_fuzzed = request_str
        for fuzz_str, fuzz_value in zip(fuzz_dict.keys(), lines):
            request_str_fuzzed = request_str_fuzzed.replace(fuzz_str, fuzz_value)
        method = request_str_fuzzed.split(" ", 1)[0]
        client = connection_class(host)
        client.connect()
        client.sock.send(request_str_fuzzed.encode("ascii"))
        response = response_class(client.sock, method=method)
        try:
            try:
                response.begin()
            except ConnectionError:
                client.close()
                raise
            if response.will_close:
                client.close()
        except:
            response.close()
            raise
        response_payload = response.read()
        print_lock.acquire()
        fuzz_values = "".join([f"{repr(fuzz_value)[1:-1] if len(fuzz_value) < 20 else repr(fuzz_value[:16])[1:-1] + '...':<20}" for fuzz_value in lines])
        status = f"{response.status:<7}"
        tqdm.write(f"{fuzz_values}{c(status)}{len(response_payload):<8}{response_payload.count(b' '):<8}")
        bar.update()
        print_lock.release()
        client.close()


def main():
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=intruder_runner)
        threads.append(thread)
    fuzz_strs = "".join([f"{fuzz_str:<20}" for fuzz_str in fuzz_dict.keys()])
    header_str = f"{fuzz_strs}{'Status':<7}{'Size':<8}{'Words':<8}"
    if color_output:
        print("\033[1m" + header_str + "\033[0m")
    else:
        print(header_str)
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
