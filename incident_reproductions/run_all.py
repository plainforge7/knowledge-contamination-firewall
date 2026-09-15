from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

from incident_reproductions.hermes_17164 import run_reproduction as run_17164
from incident_reproductions.hermes_2670 import run_reproduction as run_2670
from incident_reproductions.openviking_4193 import run_reproduction as run_4193


def main() -> None:
    with TemporaryDirectory(prefix="knowledge-firewall-incidents-") as temp_dir:
        result = {
            "data_policy": "synthetic_only",
            "production_systems_touched": False,
            "incidents": [
                run_4193(),
                run_2670(),
                run_17164(Path(temp_dir)),
            ],
        }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

