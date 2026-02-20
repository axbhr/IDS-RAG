import time
import os
import random

LOG_FILE = "./logs/conn.log"

if not os.path.exists("./logs"):
    os.makedirs("./logs")

# Standard Zeek conn.log fields
FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
]


def write_header(f):
    f.write("#separator \\x09\n")
    f.write("#set_separator ,\n")
    f.write("#empty_field (empty)\n")
    f.write("#unset_field -\n")
    f.write("#path conn\n")
    f.write("#open " + time.strftime("%Y-%m-%d-%H-%M-%S") + "\n")
    f.write("#fields\t" + "\t".join(FIELDS) + "\n")
    f.write(
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\n"
    )


def generate_log():
    ts = str(time.time())
    uid = "C" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=17))

    # Attack Scenarios based on threat intel
    attacks = [
        # Normal HTTP Traffic (Benign)
        [
            ts,
            uid,
            "192.168.1.10",
            "43210",
            "10.0.0.5",
            "80",
            "tcp",
            "http",
            "0.500000",
            "150",
            "3000",
            "SF",
            "T",
            "F",
            "0",
            "ShADadFf",
            "5",
            "300",
            "4",
            "200",
            "(empty)",
        ],
        # SSH Brute Force Signature (High frequency, small packets, failing)
        # Often conn_state is REJ or S0 if port closed/firewalled, or SF if password fails quickly
        [
            ts,
            uid,
            "192.168.1.100",
            "55555",
            "10.0.0.5",
            "22",
            "tcp",
            "-",
            "0.010000",
            "0",
            "0",
            "S0",
            "T",
            "F",
            "0",
            "S",
            "1",
            "60",
            "0",
            "0",
            "(empty)",
        ],
        # Port Scanning (SYN Scan)
        [
            ts,
            uid,
            "192.168.1.200",
            "44444",
            "10.0.0.5",
            str(random.randint(20, 1000)),
            "tcp",
            "-",
            "0.001000",
            "0",
            "0",
            "S0",
            "T",
            "F",
            "0",
            "S",
            "1",
            "40",
            "0",
            "0",
            "(empty)",
        ],
        # Data Exfiltration (Large Upload)
        [
            ts,
            uid,
            "192.168.1.50",
            "33333",
            "1.2.3.4",
            "443",
            "tcp",
            "ssl",
            "300.000000",
            "5000000",
            "500",
            "SF",
            "T",
            "F",
            "0",
            "ShAdDaFf",
            "10000",
            "5200000",
            "20",
            "1000",
            "(empty)",
        ],
    ]

    entry = random.choice(attacks)
    entry[0] = str(time.time())

    line = "\t".join(entry)
    print(f"Adding log: {line}")
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    print(f"Generating dummy Zeek TSV logs to {LOG_FILE}...")

    # Write header if file is empty or doesn't exist
    if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        with open(LOG_FILE, "w") as f:
            write_header(f)

    try:
        while True:
            generate_log()
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopped.")
