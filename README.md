# 🛑 Rust Deauth Packet Sender

This project is a simple Rust-based tool that sends deauthentication packets to a specified target device on a wireless network. It is designed for educational and testing purposes only (e.g., auditing your own network). The script uses the `pcap` crate to send raw packets and supports spoofing the sender MAC address.

> ⚠️ **Warning**  
> This tool can disrupt wireless networks and is **illegal** to use on networks you do not own or have explicit permission to test.  
> Use responsibly and only in environments where you have authorization.

---

## 🔧 Features

- Sends crafted 802.11 deauthentication frames.
- Allows spoofing of source MAC address (e.g., access point).
- Accepts command-line arguments for target/source MAC, interval, and packet count.
- Includes a delay between packet transmissions to avoid overwhelming the network.

---

## 📦 Requirements

- Rust (latest stable version recommended)
- A wireless card that supports monitor mode
- Linux or another OS that supports raw packet injection
- Root privileges

---

## 🚀 Usage

### 🔧 Build

```bash
git clone https://github.com/TheBetterQwerty/Rust-Deauther.git
cd Rust-Deauther
cargo build --release
```

### ▶️ Run

```bash
sudo ./target/release/deauth_tool -t <target_mac> -s <source_mac> [--packets <n>] [--interval <seconds>]
```

### 🧪 Example

```bash
sudo ./deauth_tool -t ff:ff:ff:ff:ff:ff -s 11:22:33:44:55:66 --packets 10 --interval 1
```

This will send 10 deauth packets (1 second apart) from `11:22:33:44:55:66` to the target broadcast MAC address.

---

## 📝 Options

| Flag             | Description                                             |
| ---------------- | ------------------------------------------------------- |
| `-t <mac>`       | **Target MAC address** (device to deauthenticate)       |
| `-s <mac>`       | **Source MAC address** (usually the AP/router MAC)      |
| `--packets <n>`  | Number of deauth packets to send (default: infinite)    |
| `--interval <s>` | Interval between packets in seconds (default: 1 second) |
| `-h, --help`     | Show help message                                       |

---

## ⚙️ How It Works

* The tool crafts a radiotap + 802.11 deauth frame with specified target/source MAC addresses.
* It injects the packet using a wireless interface in **monitor mode**.
* Spoofed deauth packets simulate a real disconnection frame, which causes the target device to disconnect from the network.

---

## 🛡️ Legal Disclaimer

This tool is intended for educational purposes only.
Do not use it on networks you do not own or operate without proper authorization.
The authors are not responsible for any misuse of this tool.

---

## 👨‍💻 Author

Developed by \[qwerty\]

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for more information.

---
