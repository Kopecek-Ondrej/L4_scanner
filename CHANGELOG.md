# Implemented functionality
* Command-line interface for selecting network interface, TCP/UDP port ranges, target host, and timeout.
* Host resolution and scanning support for IPv4 and IPv6 targets.
* TCP port probing and state evaluation for requested port ranges.
* UDP port probing and state evaluation for requested port ranges.
* Concurrent send/receive scanning architecture with packet capture-based response handling.
* Input validation and user-facing error handling for invalid arguments and runtime failures.
* Automated test suite (Google Test) with unit and integration-style tests.

# Known limitations
* Function get_available_source_port() should ensure that once i get a port, it will me mine until I let go of it. However, I haven't tested this under different situations.
* All provided tests do succeed if I run them in WSL with devshell enabled. However, I had some trouble running all tests on the provided VM. My explanation is that the VM is "laggy" compared to WSL and system calls such as bind() behave differently. Simply put, I believe that VM has additional latency that makes the timeout run out.
* Although I alse ran tests on native Ubuntu 24.04 I cannot guarantee that the tests will all pass. They do pass if run separatly, but together there is some mishappenings going on. I was not able to resolve it.