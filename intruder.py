import argparse
import http.client
import operator
import re
import sys
import threading
import time
from functools import reduce
from re import Pattern
from typing import Type, List
from urllib.parse import quote

from tqdm.auto import tqdm

program_terminated: bool = False


def create_argument_parser():
    parser = argparse.ArgumentParser(
        prog="intruder",
        description="Burp-like intruder that lets you send requests with fuzzed headers/body/url",
        epilog="Example: intruder -w wordlist.txt -r request.txt -h google.com",
        add_help=False
    )
    parser.add_argument(
        "--help",
        action="help",
        help="Show this message"
    )
    parser.add_argument(
        "-w",
        metavar="<filename or list>",
        help="Wordlist file or comma separated list e.g.: USER:path/to/wordlist1.txt,PASS:path/to/wordlist2.txt",
        required=True
    )
    parser.add_argument(
        "-r",
        metavar="<filename>",
        help="Request file",
        required=True
    )
    parser.add_argument(
        "-h",
        metavar="<host>",
        help="Host e.g. google.com",
        required=True
    )
    parser.add_argument(
        "-d",
        metavar="<float>",
        help="Delay between requests in seconds e.g. 0.1",
        default="0"
    )
    parser.add_argument(
        "-t",
        metavar="<int>",
        help="Number of threads",
        default="40"
    )
    parser.add_argument(
        "-p",
        metavar="<protocol>",
        help="Protocol (http or https)",
        default="http"
    )
    parser.add_argument(
        "-c",
        help="Colorize output",
        action="store_true"
    )
    parser.add_argument(
        "-ir",
        metavar="<regex>",
        help="Include responses with content body matching regex (if response is also excluded by -n it will still be included)"
    )
    parser.add_argument(
        "-er",
        metavar="<regex>",
        help="Exclude responses with content body matching regex (if response is also included by -m it will not be excluded)"
    )
    return parser


def strip_endline(line: str) -> str:
    if line.endswith("\r\n"):
        return line.removesuffix("\r\n")
    if line.endswith("\n"):
        return line.removesuffix("\n")
    return line


def colorize_status_code(status_code: str) -> str:
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


class PrintContext:
    def __init__(self,
                 progress_bar: tqdm,
                 color_output: bool,
                 include_regex: Pattern | None,
                 exclude_regex: Pattern | None
                 ):
        self.progress_bar = progress_bar
        self.color_output = color_output
        self.include_regex = include_regex
        self.exclude_regex = exclude_regex
        self.lock = threading.Lock()


class Request:
    def __init__(self,
                 raw: str,
                 connection_class: Type[http.client.HTTPConnection] | Type[http.client.HTTPSConnection],
                 host: str,
                 print_context: PrintContext
                 ):
        self.raw = raw
        self.connection_class = connection_class
        self.host = host
        self.print_context = print_context
        self.add_content_length()
        self.method = None
        self.infer_method()

    def infer_method(self) -> None:
        self.method = self.raw.split(" ", 1)[0]

    def add_content_length(self) -> None:
        headers, content = self.raw.split("\r\n\r\n", 1)
        content_length = len(content.removesuffix("\r\n\r\n"))
        self.raw = headers + f"\r\nContent-Length: {content_length}\r\n\r\n" + content

    def send(self):
        client = self.connection_class(self.host)
        client.connect()
        try:
            client.sock.send(self.raw.encode("ascii"))
            response = http.client.HTTPResponse(client.sock, method=self.method)
            response.begin()
        finally:
            client.close()
        return Response(
            response,
            self.print_context
        )


class Response:
    def __init__(self,
                 response: http.client.HTTPResponse,
                 print_context: PrintContext
                 ):
        self.response = response
        self.print_context = print_context
        self.content_length = self.response.getheader("Content-Length")
        if self.has_to_read():
            self.payload = self.response.read()
        self.response.close()
        if self.content_length is None:
            self.content_length = len(self.payload)

    def has_to_read(self):
        if self.print_context.include_regex is not None:
            return True
        if self.print_context.exclude_regex is not None:
            return True
        if self.content_length is None:
            return True
        return False

    def print(self, fuzz_values: List[str]):
        if self.print_context.include_regex is not None and self.print_context.include_regex.search(self.payload.decode("utf-8")) is None:
            return
        if self.print_context.exclude_regex is not None and self.print_context.exclude_regex.search(self.payload.decode("utf-8")) is not None:
            return
        self.print_context.lock.acquire()
        try:
            fuzz_values = "".join([
                f"{repr(fuzz_value)[1:-1] if len(fuzz_value) < 20 else repr(fuzz_value[:16])[1:-1] + '...':<20}"
                for fuzz_value in fuzz_values
            ])
            status = f"{self.response.status:<8}"
            if self.print_context.color_output:
                status = colorize_status_code(status)
            tqdm.write(f"{fuzz_values}{status}{self.content_length:<8}")
        finally:
            self.print_context.lock.release()


class FuzzRequest:
    def __init__(self,
                 filename: str,
                 fuzz_keywords: List[str],
                 protocol: str,
                 host: str,
                 print_context: PrintContext
                 ):
        self.raw = None
        self.fuzz_keywords = fuzz_keywords
        self.host = host
        if protocol == "http":
            self.connection_class = http.client.HTTPConnection
        elif protocol == "https":
            self.connection_class = http.client.HTTPSConnection
        else:
            raise ValueError(f"Unknown protocol '{protocol}'")
        self.print_context = print_context
        self.init_request_from_file(filename)
        self.adjust_content_headers()

    def init_request_from_file(self, filename: str) -> None:
        with open(filename, "r") as f:
            content = "\r\n".join([strip_endline(line) for line in f.readlines()])
            if not content.endswith("\r\n\r\n"):
                if content.endswith("\r\n"):
                    content = content + "\r\n"
                else:
                    content = content + "\r\n\r\n"
            self.raw = content

    def adjust_content_headers(self):
        headers, content = self.raw.split("\r\n\r\n", 1)
        headers = [
            header
            for header in headers.split("\r\n")
            if not header.startswith("Content-Length") and not header.startswith("Accept-Encoding")
        ]
        headers = headers + ["Accept-Encoding: identity"]
        self.raw = "\r\n".join(headers) + "\r\n\r\n" + content

    def get_request(self, fuzz_values: List[str]) -> Request:
        fuzzed_request = self.raw
        for keyword, value in zip(self.fuzz_keywords, fuzz_values):
            fuzzed_request = fuzzed_request.replace(keyword, quote(value))
        return Request(
            fuzzed_request,
            self.connection_class,
            self.host,
            self.print_context
        )


class Intruder:
    def __init__(self,
                 lock: threading.Lock,
                 end_barrier: threading.Barrier,
                 fuzz_request: FuzzRequest,
                 fuzz_keywords: List[str],
                 fuzz_values_generator,
                 delay: float,
                 print_context: PrintContext
                 ):
        self.thread = threading.Thread(target=self.run)
        self.end_barrier = end_barrier
        self.thread.daemon = True
        self.lock = lock
        self.fuzz_request = fuzz_request
        self.fuzz_keywords = fuzz_keywords
        self.fuzz_values_generator = fuzz_values_generator
        self.delay = delay
        self.print_context = print_context

    def start(self):
        self.thread.start()

    def join(self):
        self.thread.join()

    def run(self):
        global program_terminated
        while not program_terminated:
            try:
                if not self.intrude():
                    break
            except KeyboardInterrupt:
                print(f"Interrupted", file=sys.stderr)
                program_terminated = True
            except Exception as e:
                print(f"Exception occurred: {e}", file=sys.stderr)
        if self.end_barrier.wait() == 0:
            program_terminated = True

    def intrude(self) -> bool:
        fuzz_values = self.next_fuzz_values()
        if fuzz_values is None:
            return False
        request = self.fuzz_request.get_request(fuzz_values)
        response = request.send()
        response.print(fuzz_values)
        self.print_context.progress_bar.update()
        return True

    def next_fuzz_values(self):
        self.lock.acquire()
        try:
            lines = next(self.fuzz_values_generator)
            if self.delay > 0:
                time.sleep(self.delay)
            return lines
        except StopIteration:
            return None
        finally:
            self.lock.release()


def add_content_length(request: str) -> str:
    headers, content = request.split("\r\n\r\n", 1)
    content_length = len(content.removesuffix("\r\n\r\n"))
    return headers + f"\r\nContent-Length: {content_length}\r\n\r\n" + content


def print_header(fuzz_keywords: List[str], print_context: PrintContext) -> None:
    fuzz_strs = "".join([f"{fuzz_str:<20}" for fuzz_str in fuzz_keywords])
    header_str = f"{fuzz_strs}{'Status':<8}{'Size':<8}"
    if print_context.color_output:
        print_context.progress_bar.write("\033[1m" + header_str + "\033[0m")
    else:
        print_context.progress_bar.write(header_str)


def create_fuzz_values_generator(fuzz_filenames: List[str]):
    files = [open(filename, "r") for filename in fuzz_filenames]
    lines = [f.readline() for f in files]
    yield [strip_endline(line) for line in lines]
    while True:
        idx = len(lines) - 1
        while lines[idx] == "" and idx > 0:
            files[idx].close()
            files[idx] = open(list(fuzz_filenames)[idx], "r")
            lines[idx] = files[idx].readline()
            lines[idx - 1] = files[idx - 1].readline()
            idx -= 1
        if lines[idx] == "" and idx == 0:
            break
        yield [strip_endline(line) for line in lines]
        lines[-1] = files[-1].readline()


def main():
    parser = create_argument_parser()
    args = parser.parse_args()

    if ":" in args.w:
        keyword_filename = args.w.split(",")
        keyword_filename = [fuzz.split(":", 1) for fuzz in keyword_filename]
        fuzz_keywords = [keyword for keyword, _ in keyword_filename]
        fuzz_filenames = [wordlist for _, wordlist in keyword_filename]
    else:
        fuzz_keywords = ["FUZZ"]
        fuzz_filenames = [args.w]

    request_filename = args.r
    host = args.h
    num_threads = int(args.t)
    time_delay = float(args.d)
    protocol = args.p
    color_output = args.c
    include_regex = re.compile(args.ir) if args.ir is not None else None
    exclude_regex = re.compile(args.er) if args.er is not None else None

    lock = threading.Lock()
    end_barrier = threading.Barrier(num_threads)
    total_requests = reduce(operator.mul, [len(open(filename, "r").readlines()) for filename in fuzz_filenames])
    progress_bar = tqdm(
        total=total_requests,
        unit=" requests",
        colour="green" if color_output else None
    )
    print_context = PrintContext(
        progress_bar,
        color_output,
        include_regex,
        exclude_regex
    )
    fuzz_request = FuzzRequest(
        request_filename,
        fuzz_keywords,
        protocol,
        host,
        print_context
    )
    fuzz_values_generator = create_fuzz_values_generator(fuzz_filenames)

    print_header(fuzz_keywords, print_context)

    intruders = [
        Intruder(
            lock,
            end_barrier,
            fuzz_request,
            fuzz_keywords,
            fuzz_values_generator,
            time_delay,
            print_context
        ) for _ in range(num_threads)
    ]

    for intruder in intruders:
        intruder.start()
    try:
        while not program_terminated:
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
