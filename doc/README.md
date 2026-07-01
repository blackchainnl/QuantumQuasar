Blackcoin
=============

Setup
---------------------
Blackcoin is the original Blackcoin client and it builds the backbone of the network. It downloads and, by default, stores the entire history of Blackcoin transactions, which requires a few hundred gigabytes of disk space. Depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more.

To download Blackcoin, visit [blackcoinmore.org](https://blackcoinmore.org).

Running
---------------------
The following are some helpful notes on how to run Blackcoin on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/blackcoin-qt` (GUI) or
- `bin/blackcoind` (headless)

### Windows

Unpack the files into a directory, and then run blackcoin-qt.exe.

### macOS

Drag Blackcoin to your applications folder, and then run Blackcoin.

### Need Help?

* See the project documentation in this repository for build, wallet, RPC, and
  network operation notes.
* Check the Blackcoin community channels used by this fork before relying on
  inherited upstream support material.

Building
---------------------
The following are developer notes on how to build Blackcoin on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)
- [Android Build Notes](build-android.md)

Development
---------------------
The repository [root README](/README.md) contains relevant information on the
development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://doxygen.bitcoincore.org/)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

### Resources
* Use the issue tracker and project channels for Blackcoin-specific
  development discussion.

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [blackcoin.conf Configuration File](blackcoin-conf.md)
- [CJDNS Support](cjdns.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [Managing Wallets](managing-wallets.md)
- [Multisig Tutorial](multisig-tutorial.md)
- [P2P bad ports definition and list](p2p-bad-ports.md)
- [PSBT support](psbt.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Transaction Relay Policy](policy/README.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
