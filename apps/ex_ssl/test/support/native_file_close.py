"""Run the native-close fixture in a bounded, separately loaded BEAM process."""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


def run(config):
    directory = Path(config["directory"])
    support = Path(__file__).resolve().parent
    darwin = sys.platform == "darwin"
    library = directory / ("close.dylib" if darwin else "close.so")
    compiler = shutil.which("cc")
    if compiler is None:
        raise RuntimeError("native-close integration requires an existing C compiler")

    flags = ["-dynamiclib"] if darwin else ["-shared", "-fPIC"]
    compiled = subprocess.run(
        [compiler, *flags, "-Wall", "-Wextra", "-Werror", "-o", str(library),
         str(support / "native_file_close.c"), *([] if darwin else ["-ldl"])],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=15,
        check=False,
    )
    if compiled.returncode != 0:
        raise RuntimeError(compiled.stdout.decode(errors="replace"))

    root = Path(config["erlang_root"])
    bindir = root / ("erts-" + config["erts_version"]) / "bin"
    env = os.environ.copy()
    env.update(
        ROOTDIR=str(root), BINDIR=str(bindir), EMU="beam", PROGNAME="erl",
        ERL_FLAGS="", ERL_AFLAGS="", ERL_ZFLAGS="",
        HTTP_FETCH_NATIVE_CLOSE_TARGET=str(directory / "policy"),
        HTTP_FETCH_NATIVE_CLOSE_ENTERED=str(directory / "entered"),
        HTTP_FETCH_NATIVE_CLOSE_RELEASE=str(directory / "release"),
        HTTP_FETCH_NATIVE_CLOSE_DIRECTORY=str(directory),
        HTTP_FETCH_NATIVE_CLOSE_SCENARIO=config["scenario"],
    )
    env["DYLD_INSERT_LIBRARIES" if darwin else "LD_PRELOAD"] = str(library)
    argv = [str(bindir / "erlexec"), "+S", "2:2", "+SDio", "2", "+SDcpu", "1",
            "-noshell", "-pa", *config["code_paths"], "-s", "elixir", "start_cli",
            "-extra", str(support / "native_file_close.exs")]
    child = subprocess.Popen(
        argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    result = {"scenario": config["scenario"], "native_close": False}

    try:
        until = time.monotonic() + 7
        ready = directory / "ready"
        while not ready.exists() and child.poll() is None and time.monotonic() < until:
            time.sleep(0.005)

        result["native_close"] = ready.exists() and (directory / "entered").exists()
        (directory / "release").touch()
        output, _ = child.communicate(timeout=10)
        result["child_exit"] = child.returncode
        result["result"] = (
            "PASS" if result["native_close"] and child.returncode == 0
            and b"NATIVE_POLICY_CLOSE_PASS" in output else "FAIL"
        )
        if result["result"] != "PASS":
            result["output"] = output[-8192:].decode(errors="replace")
    finally:
        (directory / "release").touch()
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=3)
        result["child_joined"] = child.returncode is not None

    return result


if __name__ == "__main__":
    try:
        result = run(json.loads(Path(sys.argv[1]).read_text()))
    except Exception as error:
        result = {"result": "FAIL", "error": str(error)}
    print(json.dumps(result))
    sys.exit(0 if result["result"] == "PASS" else 1)
