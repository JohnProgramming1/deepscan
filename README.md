# deepscan

See every device on your network **by name**, not just a list of MAC addresses, in a fast, keyboard-driven terminal app.

`arp -a` tells you `a4:83:e7:1f:22:0c`. deepscan tells you that's **Johns-iPhone**, an Apple device on 4 ms ping with AirPlay open, and that it's the first time it's been on your network.

## Install

**macOS / Linux**

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR-GITHUB-USERNAME/deepscan/main/install.sh | bash
```

Then open a new terminal window and run `deepscan`. You need Python 3.8 or newer. Most Macs and Linux machines already have it.

**Windows** (in PowerShell or Command Prompt)

```
py -m pip install --user pipx
py -m pipx ensurepath
py -m pipx install https://github.com/YOUR-GITHUB-USERNAME/deepscan/archive/refs/heads/main.zip
```

Then open a new terminal and run `deepscan`. Windows Terminal makes it look its best.

## Usage

```
deepscan                 scan your network
deepscan 10.0.0.0/24     scan a specific subnet
deepscan help            show all keys
```

| Key | What it does |
| --- | --- |
| ↑ ↓ | Move through devices |
| enter | Open a device's full page |
| / | Search by name, IP, vendor, type or port |
| tab | Jump between the device list and the groups sidebar |
| r | Rescan |
| s | Change sort (IP, name, type, ping) |
| t | Next color theme |
| e | Export everything to a CSV file |
| c | Copy the selected IP |
| b | Show or hide the sidebar |
| a | Credits |
| ctrl+p | Command palette |
| q | Quit |

On a device page: `n` gives it a nickname, `o` opens its web page (great for router settings), `c` copies its IP.

## What it shows

- **Names**, gathered three ways: reverse DNS (from your router), mDNS (Apple, Linux, printers, Chromecasts) and NetBIOS (Windows PCs)
- **Manufacturer**, from the official IEEE registry, downloaded once and then used offline
- **A best guess at the device type**: phone, PC, printer, TV, smart-home gadget, router and so on
- **Ping and TTL**, which hints at the operating system
- **About 20 common ports**, explained in plain English
- **A live ping graph** for whichever device you're looking at
- **New devices** marked with ★, and **offline devices** you've seen before
- **Nicknames** you give devices, remembered between scans

## Privacy

Everything stays on your computer in `~/.deepscan/`. Nothing is uploaded anywhere. The only download is the manufacturer list from the IEEE.

## Use it responsibly

deepscan is for networks you own or have permission to scan, like your home network. On school, work or public networks, scanning usually breaks the rules, even if you're only looking.

## Uninstall

macOS / Linux: `rm -rf ~/.deepscan/app ~/.local/bin/deepscan` (add `~/.deepscan` to also forget your device history)

Windows: `py -m pipx uninstall deepscan`

## Credits

Idea, design calls and testing by YOUR NAME. Code written with Claude, by Anthropic. Built on [Textual](https://github.com/Textualize/textual) and [Rich](https://github.com/Textualize/rich).

## License

MIT
