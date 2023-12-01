import subprocess

class IntrusionDetector:
    """A machine-learning-based intrusion detector."""

    def __init__(self, node) -> None:
        host = node

    def start(self) -> None:
        self.host.cmd(self.capture)

    def capture(self) -> None:
        subprocess.Popen(["tcpdump", "-w", "/tmp/raw/captured_traffic.pcap"])

    def detect(self) -> None:
        pass

    def respond(self) -> None:
        pass