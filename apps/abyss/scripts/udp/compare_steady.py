"""Run paired steady samples serially, with no concurrent test/build jobs."""
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys

candidate = Path(__file__).resolve().parents[2]
baseline = Path(sys.argv[1]).resolve()
evidence = candidate / "_build/udp-evidence"
evidence.mkdir(parents=True, exist_ok=True)
script = candidate / "scripts/udp/steady.exs"
metrics = ["throughput_per_second", "latency_median_us", "latency_p95_us", "latency_p99_us"]
samples = []


def environment(label, mode):
    env = dict(os.environ, ERL_FLAGS="+S 8:8", MIX_ENV="dev", ABYSS_STEADY_MODE=mode)
    env["MIX_BUILD_PATH"] = str(
        Path("/tmp/abyss-p6-steady-baseline") if label == "baseline" else candidate / "_build"
    )
    return env


for label, checkout in [("baseline", baseline), ("candidate", candidate)]:
    subprocess.run(["mix", "compile"], cwd=checkout, env=environment(label, "legacy"), check=True)

for repetition in range(1, 4):
    for label, checkout in [("baseline", baseline), ("candidate", candidate)]:
        result = subprocess.run(
            ["mix", "run", "--no-compile", str(script)],
            cwd=checkout, env=environment(label, "legacy"), capture_output=True, text=True,
        )
        log = f"p6-steady-paired-{label}-{repetition}.log"
        (evidence / log).write_text(result.stdout + result.stderr)
        if result.returncode or "STEADY_PASS" not in result.stdout:
            raise RuntimeError(f"{log}: exit {result.returncode}")
        values = {key: float(re.search(rf"{key}: ([\d.]+)", result.stdout)[1]) for key in metrics}
        samples.append(dict(label=label, repetition=repetition, log=log, **values))

summary = {
    label: {key: statistics.median(s[key] for s in samples if s["label"] == label) for key in metrics}
    for label in ["baseline", "candidate"]
}
output = dict(runtime="Elixir 1.18.4 / OTP 27 / ERTS 15.2.7.4", schedulers=8,
              workload="legacy; 500 warmup + 3000 sequential 64-byte request/replies",
              samples=samples, median_of_three=summary)
(evidence / "p6-steady-paired.json").write_text(json.dumps(output, indent=2) + "\n")
print(json.dumps(output, indent=2))
