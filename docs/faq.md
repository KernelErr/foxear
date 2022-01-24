## FAQ

## Can not find `-lbcc`

1. Install [bcc](https://github.com/iovisor/bcc) first.
2. Make a symbol link for `libbcc.so` like: `sudo ln -s /usr/lib/x86_64-linux-gnu/libbcc.so.0 /usr/lib/x86_64-linux-gnu/libbcc.so`.