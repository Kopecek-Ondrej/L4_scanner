# PROJECT OVERVIEW
This project is a L4 network scanner that probes TCP and UDP ports on IPv4/IPv6 hosts. It includes a CLI for selecting interface, target, and port ranges, plus a test suite for validating parser logic and scanning behavior. This aplicatoin behaves similarly to a program called nmap.

## Command for building
 ```c
make
```
and cleaning
 ```c
make clean
```
## Command to run program
 ```bash
./ipk-L4-scan -i INTERFACE [-u PORTS] [-t PORTS] HOST [-w TIMEOUT] [-h | --help]
```
If no timeout is provided the default is one second.

!!! Requires sudo privileges

## Description of implemented behaviour and features

The scanner implements basic L4 discovery for TCP and UDP ports and is designed for local and remote host checks.

Implemented features:
- Target resolution for IPv4 and IPv6 hosts.
- Interface selection from CLI arguments
- TCP port scanning over user-defined ranges.
- UDP port scanning over user-defined ranges.
- Support for scanning multiple ports in a single run.

Implemented behaviour:
- Parses command-line input, validates it, and builds an internal scan configuration.
- Sends probe packets to requested ports on the selected target.
- Waits for responses within configured timeout windows.
- Classifies ports based on observed network responses.
- Prints results for each requested protocol and port.

# Design decisions
This program is structred to three modes; modet that shows possible interface, mode that shows help info, mode for scanning.
Based on these modes that are established in main(), I tried to create corresponding modules. (.h and .c files)

Scanning is based on two threads. One is for receiving and the second one for sending.

The most outer loop of of sending packets is based on destination addresses. For each address I send both TCP and UDP packets.
Source port is determined at the begging of scanning with function that allocates a port capable of both sending/receiving TCP and UDP.
The main logic of scanning is based on two thread implemenation. First, I create a thread for receiving packets. I use appropriate libpcap function with a filter. This filter is established using the source port that I mentioned before.
The main thread has to wait until the rx thread is ready. Once, that is done, all packets are sent. Both threads modify a shared resource Table_t table. This variable is used for modifiying information about packets. 

Breaking decision was to use libnet library. This way I could create raw packets far more easily than without it.

# Testing
I chose Google test as the testing framework for this project. The main reason was that it was included in the devshell description for C/C++. The second reason was that I have already encountered Gtests before.
Important to mention; Most of these tests I generated using provided Gemini chatbot.
I tried to devide the tests into logically separated files. Files _test_cli_parser.cpp_, _test_destination.cpp_ and _test_source.cpp_ containt unit tests that helped me verify basic functionality. 

File _test_scanner.cpp_ holds tests that test the overall functionality.
Tests are made only on local interface with localhost as destination. I believe there was hardly any other way to test it.
I tested sending single and multiple packets to both IPv4 and IPv6 addresses using TCP and UDP.
Additionally I tested some edge-case I came up with, such as:
* Scanning 0.0.0.0 which resulted in FILTERED as has also nmap on WSL Ubuntu 24.04
* Scanning with minimal timeout; resulted correctly and marked all ports as FILETERED. No other realistical option.
* Scanning ports 0 and 65535
* Scanning the same port multiple times in one command; results in n-print outs of the proccesed port.

Despite WSL Ubuntu 24.04 a I have also tested it on native Ubuntu 24.04.
All tests passed the same as on the WSL.
It was important to test on native Linus distro, because I needed it to test targeting ipv6.

#### Result made on Native Ubuntu
 ```python
xxx@xxx:~/Documents/IPKP1/L4_scanner$ sudo ./ipk-L4-scan -i tun0 -t 80-83 -u 80-83 scanme.nmap.org
2600:3c01::f03c:91ff:fe18:bb2f 80 tcp open
2600:3c01::f03c:91ff:fe18:bb2f 81 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 82 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 83 tcp closed
2600:3c01::f03c:91ff:fe18:bb2f 80 udp closed
2600:3c01::f03c:91ff:fe18:bb2f 81 udp closed
2600:3c01::f03c:91ff:fe18:bb2f 82 udp closed
2600:3c01::f03c:91ff:fe18:bb2f 83 udp closed
45.33.32.156 80 tcp open
45.33.32.156 81 tcp closed
45.33.32.156 82 tcp closed
45.33.32.156 83 tcp closed
45.33.32.156 80 udp closed
45.33.32.156 81 udp closed
45.33.32.156 82 udp closed
45.33.32.156 83 udp closed

```
These results have been verified with the same results from nmap.

#### Command to run tests
 ```python
make test
```
!!! Requires sudo privileges

I implemented 44 tests with these results:
 ```c
[----------] Global test environment tear-down
[==========] 44 tests from 11 test suites ran. (19121 ms total)
[  PASSED  ] 44 tests.
```


# Known Limitations

The scanner is rather slower than would have wanted. Feeding it about 1000 ports takes more than 10 minutes. Behaviour in such scenarios
is unknown to me, because I haven't checked the answers.
Furhther known limitations are listed in CHANGELOG.md.

# References/Sources used

* I used provided Gemini chatbot and Github copilot (mainly for discovering memory leaks).
* Nmap: The Art of Port Scanning. Online. Available from: https://nmap.org/nmap_doc.html#port_unreach [Accessed 17 March 2026].
* TCP SYN (Stealth) Scan (-sS) | Nmap Network Scanning. Online. Available from: https://nmap.org/book/synscan.html [Accessed 17 March 2026].
* Port scanner, 2024. Wikipedia. Online. Available from: https://en.wikipedia.org/w/index.php?title=Port_scanner&oldid=1225200572 [Accessed 17 March 2026].
