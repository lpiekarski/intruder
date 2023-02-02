import http.client
import argparse
import sys
import threading
import time

parser = argparse.ArgumentParser(
    prog="Intruder",
    description="Burp-like intruder that lets you send requests with fuzzed headers/body/url",
    epilog="",
    add_help=False
)
parser.add_argument("--help", action="help")
parser.add_argument("-w", help="Wordlist file or comma separated list eg: USER:path/to/wordlist1.txt,PASS:path/to/wordlist2.txt")
parser.add_argument("-r", help="Request file")
parser.add_argument("-h", help="Host")
parser.add_argument("-d", help="Delay between requests in seconds", default="0")
parser.add_argument("-t", help="Number of threads", default="40")
parser.add_argument("-p", help="Protocol (http or https)", default="http")

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
        fuzz_values = "".join([f"{fuzz_value:<30}" for fuzz_value in lines])
        print(f"{fuzz_values}{response.status:>4}{response.length:>8}{response_payload.count(b' '):>8}")
        print_lock.release()
        client.close()


def main():
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=intruder_runner)
        threads.append(thread)
    fuzz_strs = "".join([f"{fuzz_str:<30}" for fuzz_str in fuzz_dict.keys()])
    print(f"{fuzz_strs}{'Status':>4}{'Size':>8}{'Words':>8}")
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
