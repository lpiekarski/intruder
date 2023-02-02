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
parser.add_argument("-w", help="Wordlist file")
parser.add_argument("-r", help="Request file")
parser.add_argument("-h", help="Host")
parser.add_argument("-d", help="Delay between requests in seconds", default="0")
parser.add_argument("-t", help="Number of threads", default="40")
parser.add_argument("-p", help="Protocol (http or https)", default="http")

args = parser.parse_args()
wordlist_file = args.w
request_file = args.r
host = args.h
num_threads = int(args.t)
time_delay = float(args.d)
protocol = args.p
lock = threading.Lock()
printlock = threading.Lock()
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


request_str = get_request()


def get_wordlist_line():
    with open(wordlist_file, "r") as f:
        while True:
            line = f.readline()
            if line == "":
                break
            yield line


wordlist_lines = get_wordlist_line()


def intruder_runner():
    while True:
        lock.acquire()
        try:
            fuzz = next(wordlist_lines)
            fuzz = fuzz.rstrip()
        except StopIteration:
            lock.release()
            break
        if time_delay > 0:
            time.sleep(time_delay)
        lock.release()
        request_str_fuzzed = request_str.replace("FUZZ", fuzz)
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
        printlock.acquire()
        print(f"{fuzz:<30}{response.status:>4}{response.length:>8}{response_payload.count(b' '):>8}")
        printlock.release()
        client.close()


def main():
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=intruder_runner)
        threads.append(thread)
    print(f"{'Payload':<30}{'Status':>4}{'Size':>8}{'Words':>8}")
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
