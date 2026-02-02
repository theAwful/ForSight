# Tool modularity and versioning

ForSight is designed so tools can be swapped or updated without changing core logic.

## How tools are wired today

1. **Config** (`app/config.py`)  
   Each tool has a path (e.g. `nmap_path`, `dirb_path`). Defaults assume the tool is on `PATH`. Override via env: `FORSIGHT_NMAP_PATH`, `FORSIGHT_DIRB_PATH`, etc.

2. **Runners** (`app/runners/`)  
   One module per domain (e.g. `web_host.py`, `recon.py`). Each runner is a function that builds CLI args from `settings.*_path` and calls `run_tool_stream()` or `run_tool()`. No hardcoded tool names in the runner body—only in config.

3. **Checklist** (`app/checklist.py`)  
   Checklist items reference a `runner_key`. The registry (`app/runners/__init__.py`) maps `runner_key` → runner function. Adding/removing a tool = add/remove checklist item + registry entry (+ optional config + runner).

4. **System vs venv tools**  
   Most tools are system binaries (nmap, dirb, etc.); override with `FORSIGHT_*_PATH` if needed. Python-based tools that must run with the backend’s venv can use the venv’s script path when available; otherwise use the configured path.

## Swapping a tool

- **Same CLI, different binary:** Set the corresponding `FORSIGHT_*_PATH` to the new binary (or script). No code change.
- **Different tool, same phase:** Add a new runner that matches the phase’s contract (same signature as existing runners), register it under a new `runner_key`, add a checklist item that uses that key. Optionally deprecate/remove the old checklist item.

## Adding a new tool

1. Add path to `app/config.py` (and optional env in `.env.example`).
2. Implement a runner (same async signature: `project_id`, `ips`, `domains`, `results_dir`, `stream_path`, `job_id`, `use_nmap`, `**kwargs` → return code, stdout, stderr, path).
3. Register in `app/runners/__init__.py` and add a checklist item in `app/checklist.py`.

## Future-proofing (ideas, not required now)

- **Versioning:** Runners could call `tool --version` (or equivalent) and log it in the job output or a small manifest. No schema change.
- **Updates:** Document “update tools” as: update system packages or `pip install -r requirements.txt` and restart. Optional: a small script or admin endpoint that runs `tool --version` for each configured tool and surfaces it in the UI.
- **Modularity:** Keep “one runner per tool” and “config holds paths.” To support pluggable bundles later, runners could be loaded from a separate package or directory that implements the same runner contract; the registry would then be built from that package instead of hardcoded imports. Not needed until you have many optional tools.
- **Security updates:** Rely on OS/package updates and `pip install -U`; optionally track CVE feeds for known tools and show a “check for updates” hint in settings. No change to current runner behavior.

Nothing in this doc requires changing existing behavior; it describes the current design and optional extensions.
