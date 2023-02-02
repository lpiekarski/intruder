import http.client
import argparse
import threading
import time

parser = argparse.ArgumentParser(
    prog="Intruder",
    description="Burp-like intruder that lets you send requests with fuzzed headers/body/url",
    epilog=""
)
parser.add_argument("-w", help="Wordlist file")
parser.add_argument("-r", help="Request file")

args = parser.parse_args()
lock = threading.Lock()
printlock = threading.Lock()
time_delay = 0.1


def get_request():
    with open(args.r, "r") as f:
        content = "\r\n".join([line.removesuffix('\r\n').removesuffix('\n') for line in f.readlines()])
        if not content.endswith("\r\n\r\n"):
            if content.endswith("\r\n"):
                content = content + "\r\n"
            else:
                content = content + "\r\n\r\n"
        return content


request_str = get_request()


def get_wordlist_line():
    with open(args.w, "r") as f:
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
        response_class = http.client.HTTPResponse
        client = http.client.HTTPConnection("google.com")
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


num_threads = 40
threads = []
for _ in range(num_threads):
    thread = threading.Thread(target=intruder_runner)
    threads.append(thread)
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
