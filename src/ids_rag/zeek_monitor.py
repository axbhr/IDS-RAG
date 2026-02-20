import time
import json
import os
from typing import List, Dict, Generator
from datetime import datetime


class ZeekMonitor:
    def __init__(self, log_path: str, interval_seconds: int = 10):
        self.log_path = log_path
        self.interval_seconds = interval_seconds
        self._stop_flag = False

    def follow(self) -> Generator[List[str], None, None]:
        """
        Tails the Zeek log file and yields batches of raw lines (TSV) every `interval_seconds`.
        Preserves the header fields if found.
        """
        if not os.path.exists(self.log_path):
            raise FileNotFoundError(f"Zeek log file found at: {self.log_path}")

        print(f"Monitoring Zeek log (TSV mode): {self.log_path}")
        print(f"Batch interval: {self.interval_seconds} seconds")

        header_fields = None

        with open(self.log_path, "r") as f:
            # Try to find header in existing file first (if we are appending)
            # Or just start tailing.
            # For simplicity in tailing rotation, we just look at lines.

            # Go to end for tailing
            f.seek(0, 2)

            buffer: List[str] = []
            last_yield_time = time.time()

            while not self._stop_flag:
                line = f.readline()
                if line:
                    if line.startswith("#fields"):
                        header_fields = line.strip()
                    elif not line.startswith("#"):
                        buffer.append(line.strip())
                else:
                    time.sleep(0.1)

                current_time = time.time()
                if current_time - last_yield_time >= self.interval_seconds:
                    if buffer:
                        # Prepend header if we have one, to give context to the LLM
                        output_batch = []
                        if header_fields:
                            output_batch.append(header_fields)
                        output_batch.extend(buffer)

                        yield output_batch
                        buffer = []
                    last_yield_time = current_time

    def stop(self):
        self._stop_flag = True
