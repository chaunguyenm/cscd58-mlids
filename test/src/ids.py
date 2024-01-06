import subprocess
from time import strftime, gmtime
from skops.io import load

RAW_FILEPATH = "../tmp/raw/"
ANALYZED_FILEPATH = "../tmp/alayzed/"
LOG_FILEPATH = "../tmp/log/"
DEFAULT_FILEPATH = "../tmp/bin/"
MODEL_PATH = "../model/intrusion-classifier.skops"

class IntrusionDetector:
    """A machine-learning-based intrusion detector."""

    def __init__(self, node) -> None:
        host = node

    def start(self) -> None:
        self.host.cmd(self.capture)

    def capture(self) -> None:
        subprocess.Popen(["tcpdump", "-w", generate_path])

    def detect(self) -> None:
        # Analyze pcap with CIC Flow Meter
        # Save file
        loaded = load(MODEL_PATH, trusted=True)
        # print(loaded.score(X_test, y_test))

    def respond(self) -> None:
        pass

def generate_path(type) -> str:
    ts = strftime("%d%m%y-%H%M%S", gmtime())
    if type == "raw":
        return RAW_FILEPATH + ts + ".pcap"
    if type == "analyzed":
        return ANALYZED_FILEPATH + ts + ".csv"
    if type == "log":
        return LOG_FILEPATH + ts + ".txt"
    return DEFAULT_FILEPATH + ts + ".txt"