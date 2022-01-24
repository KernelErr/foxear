![Banner](./docs/images/banner.jpg)

# Fox Ear

Fox Ear is a Linux process behavior trace tool powered by eBPF.

Banner image by [Birger Strahl](https://unsplash.com/@bist31?utm_source=unsplash&utm_medium=referral&utm_content=creditCopyText) on [Unsplash](https://unsplash.com/s/photos/fox?utm_source=unsplash&utm_medium=referral&utm_content=creditCopyText). 

## Features

- Log process and its subprocesses' creation and create a graph.
- Log processes' file access.
- Log processes' TCP connection(IPv4 and IPv6).

## Documents

- [Install](./docs/install.md)
- [Example](./docs/example.md)
- [FAQ](./docs/faq.md)

## License

Fox Ear is available under the **MPL-2.0** license. You can read an [explanation](https://tldrlegal.com/license/mozilla-public-license-2.0-(mpl-2)) about it, but only the full text of MPL-2.0 has legal effect.

Fox Ear used some parts of following projects:

- Probes - [bcc](https://github.com/iovisor/bcc) (Apache-2.0)