import sys
import time
from cicflowmeter.sniffer import create_sniffer

IFACE = sys.argv[1] if len(sys.argv) > 1 else "eth0"
OUT = sys.argv[2] if len(sys.argv) > 2 else "flows.csv"

sniffer, session = create_sniffer(
    input_file=None,
    input_interface=IFACE,
    output_mode="csv",
    output=OUT,
    fields=None,
)
sniffer.start()
print(f"Sniffing on {IFACE} -> {OUT}", flush=True)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    sniffer.stop()
    try:
        session.flush_flows()
    except Exception:
        pass