# Intruder
## Installation
```commandline
pip install intruder
```

## Usage
Save request to `request.txt` as text (for example from burp), replace the part that you want to brute-force with `FUZZ` and run
```commandline
intruder -w wordlist.txt -r request.txt -h google.com -p http
```
If you want to fuzz more than 1 value, replace those values with e.g. `USER` and `PASS` and use:
```commandline
intruder -w USER:user_wordlist.txt,PASS:pass_wordlist.txt -r request.txt -h google.com -p http
```
Here is an example of `requests.txt` file:
```
GET / HTTP/2
Host: google.com
Cookie: CONSENT=PENDING+342
Sec-Ch-Ua: "Chromium";v="109", "Not_A Brand";v="99"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: FUZZ
Accept: application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
X-Client-Data: CLGQywE=
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close
```
Notice the `FUZZ` keyword in `User-Agent` header. This value will be replaced in requests with lines from wordlist one-by-one.