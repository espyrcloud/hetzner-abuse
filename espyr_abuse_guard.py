import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
os.system('clear')
FILE = "ips.txt"
STATE_DIR = Path("/var/lib/bulkblocker")
STATE_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = STATE_DIR / "state.json"

NFT_TABLE = "bulkblocker"
NFT_CHAIN_IN = "bb_input"
NFT_CHAIN_OUT = "bb_output"
NFT_SET = "blocked_cidrs"


SET = "blocked_cidrs"
CHAIN_IN = "INPUT"
CHAIN_OUT = "OUTPUT"
COMMENT = "bulkblocker"




def root():
    if os.geteuid() != 0:
        print("Run as root")
        sys.exit(1)


def run(cmd, check_rc=False, input_text=None):
    try:
        res = subprocess.run(
            cmd,
            input=input_text,
            text=True if input_text is not None else False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if check_rc and res.returncode != 0:
            raise RuntimeError(f"Command failed: {' '.join(cmd)}")
        return res.returncode == 0
    except FileNotFoundError:
        return False


def backend():
    if shutil.which("nft"):
        return "nft"
    if shutil.which("iptables") and shutil.which("ipset"):
        return "iptables"
    print("No firewall backend found (need nft OR iptables+ipset)")
    sys.exit(1)


def read_cidrs():
    if not os.path.exists(FILE):
        print("File not found: ips.txt")
        sys.exit(1)
    out = []
    with open(FILE) as f:
        for l in f:
            s = l.strip()
            if not s or s.startswith("#"):
                continue
            if "/" not in s:
                s += "/32"
            if s not in out:
                out.append(s)
    return out


def save_state(d):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(d, f)
    except Exception:
        pass


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def ask(prompt, default=None):
    try:
        s = input(prompt).strip()
        return s or default
    except EOFError:
        return default


def list_listening_ports():
    """Return set of (proto, port) tuples for listening sockets using ss(8)."""
    ports = set()

    cp = subprocess.run(["ss", "-lnt"], capture_output=True, text=True)
    if cp.returncode == 0:
        for line in cp.stdout.splitlines():

            if line.startswith("State"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                local = parts[3]

                if ":" in local:
                    port = local.rsplit(":", 1)[-1]
                    if port.isdigit():
                        ports.add(("tcp", int(port)))

    cp = subprocess.run(["ss", "-lnu"], capture_output=True, text=True)
    if cp.returncode == 0:
        for line in cp.stdout.splitlines():
            if line.startswith("State"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                local = parts[3]
                if ":" in local:
                    port = local.rsplit(":", 1)[-1]
                    if port.isdigit():
                        ports.add(("udp", int(port)))
    return ports




def ipt_allow_basics(ports, ssh_port):

    run(["iptables", "-C", CHAIN_IN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]) or \
    run(["iptables", "-I", CHAIN_IN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", COMMENT, "-j", "ACCEPT"])


    run(["iptables", "-C", CHAIN_IN, "-i", "lo", "-j", "ACCEPT"]) or \
    run(["iptables", "-I", CHAIN_IN, "-i", "lo", "-m", "comment", "--comment", COMMENT, "-j", "ACCEPT"])

    run(["iptables", "-C", CHAIN_IN, "-p", "tcp", "--dport", str(ssh_port), "-j", "ACCEPT"]) or \
    run(["iptables", "-I", CHAIN_IN, "-p", "tcp", "--dport", str(ssh_port), "-m", "comment", "--comment", COMMENT, "-j", "ACCEPT"])

    for proto, port in sorted(ports):
        if proto == "tcp" and port == ssh_port:
            continue
        spec = ["iptables", "-C", CHAIN_IN, "-p", proto, "--dport", str(port), "-j", "ACCEPT"]
        if not run(spec):
            run(["iptables", "-I", CHAIN_IN, "-p", proto, "--dport", str(port), "-m", "comment", "--comment", COMMENT, "-j", "ACCEPT"])


def ipt_apply_cidrs(cidrs):
    if shutil.which("ipset"):
        batch = f"create {SET} hash:net family inet -exist\n" + "\n".join(f"add {SET} {c}" for c in cidrs) + "\n"
        run(["ipset", "restore", "-exist"], input_text=batch)
    else:
        run(["ipset", "create", SET, "hash:net", "family", "inet", "-exist"])
        for x in cidrs:
            run(["ipset", "add", SET, x, "-exist"])

    run(["iptables", "-C", CHAIN_IN, "-m", "set", "--match-set", SET, "src", "-j", "DROP"]) or \
    run(["iptables", "-I", CHAIN_IN, "-m", "set", "--match-set", SET, "src", "-m", "comment", "--comment", COMMENT, "-j", "DROP"])

    run(["iptables", "-C", CHAIN_OUT, "-m", "set", "--match-set", SET, "dst", "-j", "DROP"]) or \
    run(["iptables", "-I", CHAIN_OUT, "-m", "set", "--match-set", SET, "dst", "-m", "comment", "--comment", COMMENT, "-j", "DROP"])


def ipt_cleanup():

    while run(["iptables", "-D", CHAIN_IN, "-m", "set", "--match-set", SET, "src", "-m", "comment", "--comment", COMMENT, "-j", "DROP"]):
        pass
    while run(["iptables", "-D", CHAIN_OUT, "-m", "set", "--match-set", SET, "dst", "-m", "comment", "--comment", COMMENT, "-j", "DROP"]):
        pass

    def del_accept(proto):

        out = subprocess.run(["iptables", "-S", CHAIN_IN], capture_output=True, text=True)
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                if COMMENT in line and f"-p {proto}" in line and "--dport" in line:

                    parts = line.split()
                    try:
                        idx = parts.index("-A")

                        parts[idx] = "-D"
                        run(["iptables"] + parts[idx:])
                    except ValueError:
                        continue
    del_accept("tcp")
    del_accept("udp")


    run(["ipset", "destroy", SET])




def nft_allow_basics(ports, ssh_port):

    run(["nft", "add", "table", "inet", NFT_TABLE])
    run(["nft", "add", "chain", "inet", NFT_TABLE, NFT_CHAIN_IN, "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"])
    run(["nft", "add", "chain", "inet", NFT_TABLE, NFT_CHAIN_OUT, "{", "type", "filter", "hook", "output", "priority", "0", ";", "}"])


    run(["nft", "add", "rule", "inet", NFT_TABLE, NFT_CHAIN_IN, "ct", "state", "established,related", "accept"]) or None
    run(["nft", "add", "rule", "inet", NFT_TABLE, NFT_CHAIN_IN, "iifname", "lo", "accept"]) or None


    run(["nft", "add", "rule", "inet", NFT_TABLE, NFT_CHAIN_IN, "tcp", "dport", str(ssh_port), "accept"]) or None


    for proto, port in sorted(ports):
        if proto == "tcp" and port == ssh_port:
            continue
        run(["nft", "add", "rule", "inet", NFT_TABLE, NFT_CHAIN_IN, proto, "dport", str(port), "accept"]) or None


def nft_apply_cidrs(cidrs):

    run(["nft", "add", "set", "inet", NFT_TABLE, NFT_SET, "{", "type", "ipv4_addr", ";", "flags", "interval", ";", "}"])

    chunk_size = 10000
    for i in range(0, len(cidrs), chunk_size):
        chunk = cidrs[i : i + chunk_size]
        if not chunk:
            continue
        elems = ", ".join(chunk)
        run(["nft", "add", "element", "inet", NFT_TABLE, NFT_SET, "{", elems, "}"])

    run(["nft", "add", "rule", "inet", NFT_TABLE, NFT_CHAIN_IN, "ip", "saddr", f"@{NFT_SET}", "drop"]) or None
    run(["nft", "add", "rule", "inet", NFT_TABLE, NFT_CHAIN_OUT, "ip", "daddr", f"@{NFT_SET}", "drop"]) or None


def nft_cleanup():

    run(["nft", "delete", "table", "inet", NFT_TABLE])




def get_current_ssh_port():
    port = 22
    try:
        with open("/etc/ssh/sshd_config", "r") as f:
            for line in f:
                ls = line.strip()
                if ls.startswith("Port ") and not ls.startswith("#"):
                    val = ls.split()[1]
                    if val.isdigit():
                        port = int(val)
                        break
    except Exception:
        pass
    return port


def set_ssh_port(new_port):
    cfg = "/etc/ssh/sshd_config"
    try:
        with open(cfg, "r") as f:
            lines = f.readlines()
        wrote = False
        for i, line in enumerate(lines):
            if line.strip().startswith("Port ") and not line.strip().startswith("#"):
                lines[i] = f"Port {new_port}\n"
                wrote = True
                break
        if not wrote:
            lines.append(f"\nPort {new_port}\n")
        with open(cfg, "w") as f:
            f.writelines(lines)

        if shutil.which("systemctl"):
            run(["systemctl", "reload", "sshd"]) or run(["systemctl", "restart", "sshd"])  
        else:
            run(["service", "ssh", "reload"]) or run(["service", "ssh", "restart"])  
        return True
    except Exception:
        return False




def do_apply():
    b = backend()
    cidrs = read_cidrs()

    # Ask SSH port
    cur = get_current_ssh_port()
    print(f"Current SSH port: {cur}")
    new_port_s = ask("Enter new SSH port (1024-65535) or press Enter to keep current: ")
    try:
        new_port = int(new_port_s) if new_port_s else cur
        if not (1 <= new_port <= 65535):
            raise ValueError
    except ValueError:
        print("Invalid port; keeping current.")
        new_port = cur

    # Collect listening ports
    ports = list_listening_ports()
    # Ensure the chosen ssh port is included
    ports.add(("tcp", new_port))

    # Save pre-state
    state = load_state()
    state.update({
        "backend": b,
        "ssh_old_port": cur,
        "ssh_new_port": new_port,
        "allowed_ports": sorted(list({(p, prt) for p, prt in ports})),
    })
    save_state(state)

    if b == "nft":
        nft_allow_basics(ports, new_port)
        nft_apply_cidrs(cidrs)
    else:
        ipt_allow_basics(ports, new_port)
        ipt_apply_cidrs(cidrs)

    if new_port != cur:
        if set_ssh_port(new_port):
            print(f"SSH port changed to {new_port} and firewall updated.")
        else:
            print("WARNING: Failed to change SSH port (firewall rules still applied).")

    print("Success: blocks applied (INPUT+OUTPUT).")


def do_cleanup():
    state = load_state()
    b = state.get("backend") or backend()


    old = state.get("ssh_old_port")
    new = state.get("ssh_new_port")
    if old and new and old != new:
        print(f"Reverting SSH port from {new} back to {old}...")
        set_ssh_port(old)


    if b == "nft":
        nft_cleanup()
    else:
        ipt_cleanup()


    try:
        if STATE_FILE.exists():
            STATE_FILE.unlink()
    except Exception:
        pass

    print("All bulkblocker rules and settings removed.")


def menu():
    print("\n====================================")
    print("  ESPYR CLOUD - Bulk IP Range Blocker")
    print("====================================")
    print("1) Block now (incoming and outgoing) + safe firewall setup + SSH port option")
    print("2) Remove all rules & restore SSH port (if changed)")
    print("0) Exit")
    return ask("Select: ").strip()


def main():
    root()
    while True:
        c = menu()
        if c == "1":
            do_apply()
        elif c == "2":
            do_cleanup()
        elif c == "0":
            print("Bye")
            break
        else:
            print("Invalid")


if __name__ == "__main__":
    main()
