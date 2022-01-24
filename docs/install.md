# Installation

Fox Ear is written in Rust, C and Python. And the minimal supported version of Linux kernel is 5.6 as eBPF features' requirements. As kernels for different Linux flavors may varies, it's recommended to compile Fox Ear on your computer rather than using a prebuilt binary.

## Requirements

- Linux kernel >= 5.6
- [bcc](https://github.com/iovisor/bcc) toolchain - [bcc/INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
  - Linux header
- Rust toolchain
- Python 3

## Compile

First, you should use `./configure` to generate configure fitting your kernel.

```
$ ./configure
```

Then use `cargo` to compile.

```
$ cargo build --release
```

Or you can use `cargo install --path .` to install Fox Ear and add it into your path.

## Usage

Check [Example](./example.md).
