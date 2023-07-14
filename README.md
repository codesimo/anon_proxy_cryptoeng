# Anonymous proxy re‐encryption
Prototype implementation of two schemes described in the `Anonymous proxy re-encryption` paper, avaiable [here](docs/SLWL11%20-%20Anonymous%20proxy%20re%E2%80%90encryption.pdf).

The schemes implemented are:
- `The modified ElGamal encryption` described in section 3.2, called `lib-elgamal-mod` in the sources
- `Anonymous proxy re-encryption` described in section 4.1, called `lib-anon-proxy` in the sources

## Requirements
### Libraries:
- [GMP](https://gmplib.org/)
- [Nettle](https://www.lysator.liu.se/~nisse/nettle/)

### Tools:
- [gcc](https://gcc.gnu.org/) / clang
- make
- [CMake](https://cmake.org/)

## Directory Structure
The project is structured as follows:

```shell
.
├── bin # contains the executables
├── docs # contains the paper
├── examples # contains two examples of usage
├── libs-mdr # contains utility libraries made by professor Mario Di Raimondo
├── src # contains the source files
└── test # contains the test/bench files
```

## Building
Move to the root directory and type:
```shell
make
```

You can change some params in the `CMakeLists.txt` file and rebuild the `Makefile` typing:

```shell
cmake .
```

## Usage

After building, you will find all the executables in the `bin` folder. You can see the `examples` in the [examples/](examples/) folder to learn how to use the libraries.

## Testing and benchmarking

Testing and benchmarking is avaiable with `test-elgamal-mod` and `test-anon-proxy` binaries.

Usage of `test-elgamal-mod`:
```
./test-elgamal-mod [verbose|quiet] [lambda 80|112|128] [seed <n>] [message <n>] [use-pp] [bench]
```

Usage of `test-anon-proxy`:
```
./test-anon-proxy [verbose|quiet] [all|original|proxy] [lambda 80|112|128] [seed <n>] [message <n>] [g-pp] [pk-pp] [bench]
```

## References

- [Anonymous proxy re-encryption](https://onlinelibrary.wiley.com/doi/full/10.1002/sec.326)
- [GMP](https://gmplib.org/)
- [Nettle](https://www.lysator.liu.se/~nisse/nettle/)
- [Mario di Raimondo](https://diraimondo.dmi.unict.it/)
- [Crypto Engineering](https://diraimondo.dmi.unict.it/teaching/crypto/)
- [README.md and directory structure of this project](https://github.com/TendTo/Id-based-Proxy-Signature-Scheme-with-Message-Recovery)