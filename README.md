# BTC
Yet another BTC client

# Why?
To figure out how cryptocurrencies work in general and research mining.

# Hashrate

Device | Where | Hashrate, MiH/s
------ | ------| ---------------
AMD Radeon Pro 455  | MacBook Pro 15" 2016 | 180
GeForce RTX 2080 Ti | My Gaming Beast PC   | 3360

The miner reaches 8-leading-zeros hash in a few seconds.

Unfortunately, such hash rate it is not practical nowadays, since the target has 18 leading zeroes.

# Build

## Unix-like

It's a typical CMake project, but requires a few adjustments:

* Latest gcc or cland supporing C++17 or later, and
* OpenSSL from Homebrew (Linux is fine, probably).

I use:

```
mkdir b && cd b
cmake -DCMAKE_C_COMPILER=gcc-8                            \
      -DCMAKE_CXX_COMPILER=g++-8                          \
      -DCMAKE_BUILD_TYPE=Release                          \
      -DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl/1.0.2r \
      ..
make
```

## Windows

* Use latest MSVC supporing `/std:c++latest`, and
* CUDA SDK for OpenCL support.

Before you build the project, you need to prepare dependencies:

```
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.bat
./vcpkg.exe integrate install
./vcpkg.exe integrate boost:x64-windows
```

Then, open the project in MSVC and enjoy compiling.

# Running

Before you run the client, you need to find a peer. Run `host -a dnsseed.bluematt.me` and choose any of them you like, for instance `2406:da18:f7c:4351:ba7c:6da8:da59:b1b6` (this peer may not be available by the time you read this).

Then, simply run:

```
src/btc 2406:da18:f7c:4351:ba7c:6da8:da59:b1b6
```

It will download the whole blockhain (no integrity checks are implemented) and start to mine using the mempool.
Once it reaches the target, it `exit(0)`; the new block won't be propogated.

# GPU mining

To select a GPU as the miner, run `src/btc --opencl-info` and find your device in the list.
Then, use its number (counting from 0) as the value in `--device-id`.

For instance, my AMD Radeon Pro 455 is the third in the list, so I pass `--device-id 2`.

# Bugs

The implementation doesn't count protocol differences, misbehaving peers, and proper sharing GPU with other applications. For instance, once a peer disconnected, the client exits with an exception.

So, if you are brave enough to run this, be aware that:
* Heavy-on-GPU applications should be closed, like Chrome (otherwise all hangs and a hard reboot is required), and
* You may have to run the client multiple times if a peer drops the connection, and you see an error `Operation not permitted`.

# Roadmap

- [x] Mining on CPU (commented out)
- [x] Mining on GPU
- [ ] Mining on FPGA
- [ ] Integration with ASICs
- [ ] Distributed mining
- [ ] Integration with mining pools
- [ ] Better design of the event loop including support multiple peers and error handling
- [ ] Integrity checks for the blockchain
- [ ] Integrity guaranties for the local copy of the blockchain
