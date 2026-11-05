# mac-usage-monitor

A background CPU, GPU and memory usage logger for a Mac (Apple Silicon, macOS),
with a report command. One self-contained Python script, `usagemon.py`, run with `uv`
(PEP 723, no third-party dependencies).

## Install on a new Mac

Needs macOS on Apple Silicon and [uv](https://docs.astral.sh/uv/). No admin
rights, no privacy prompts and no third-party Python packages.

1. Install uv, if `uv --version` doesn't already work:

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

   (or `brew install uv`). Open a new terminal afterwards so `uv` is on your PATH.

2. Put this folder where it will stay, e.g. `~/Development/mac-usage-monitor`
   (clone it or copy it). The agent runs the script from this path, so if you
   move the folder later, run `./usagemon.py install` again from the new place.

3. Install and start the agent:

   ```bash
   cd ~/Development/mac-usage-monitor
   ./usagemon.py install
   ```

   This writes `~/Library/LaunchAgents/local.mac-usage-monitor.plist`,
   pointing at the `uv` it finds on your PATH and at this script, and starts it.
   It also starts at every login. The first start may take a few seconds while
   uv fetches a Python if the Mac has none it can use.

4. Check it after a minute, and read a report after a few:

   ```bash
   ./usagemon.py status
   ./usagemon.py report --since 10m
   ```

   `status` should say `agent: running` with a recent last sample. If it
   doesn't, read `~/Library/Logs/mac-usage-monitor.log`.

Docker monitoring uses the socket in `DOCKER_HOST` (as the agent sees it),
OrbStack's `~/.orbstack/run/docker.sock` or `/var/run/docker.sock`, whichever
exists first, and is skipped when there is none. To remove everything: `./usagemon.py uninstall`, then delete
`~/Library/Application Support/mac-usage-monitor/` and the log.

## Use

```bash
./usagemon.py install          # (re)install the agent; also restarts it after edits
./usagemon.py status           # agent state, db size, the sampler's own CPU cost
./usagemon.py report           # last hour
./usagemon.py report --since today
./usagemon.py report --since 2026-11-03 --until 2026-11-04 --format json
./usagemon.py report --since 6h --app Simulator --sections top,procs,spikes
./usagemon.py repair --since today --dry-run   # trim rows that claim more CPU than the machine used
./usagemon.py uninstall        # removes the agent, keeps the database
```

Data: `~/Library/Application Support/mac-usage-monitor/usage.db` (SQLite, WAL).
Log: `~/Library/Logs/mac-usage-monitor.log`. Agent:
`~/Library/LaunchAgents/local.mac-usage-monitor.plist`.
Set `USAGEMON_DB` to point any command at another database (useful for tests).

## How it samples

One long-running process (`uv run` → Python) that sleeps between polls; it
never forks per process and only forks `ps` once per sample.

| What | How | How often |
| --- | --- | --- |
| Your own processes: CPU time, RSS, reaped-children time | `proc_listallpids` + `proc_pid_rusage` via ctypes (libproc) | every 10 s |
| Other users' processes (WindowServer, coreaudiod, root daemons) | libproc may not read their CPU, so setuid `/bin/ps -x -o pid,time,rss -u <their users>` (~8 ms; a full `ps -A` with names costs ~90 ms). Path and parent come from libproc. | every 30 s |
| Whole-machine CPU | `host_statistics(HOST_CPU_LOAD_INFO)` ticks | every 15 s |
| GPU utilisation | IOKit in process (`IOAccelerator` `PerformanceStatistics`: Device / Renderer / Tiler %) | every 15 s |
| Per-process GPU time | IOKit: each `AGXDeviceUserClient`'s `accumulatedGPUTime` by creator pid (what Activity Monitor's GPU column uses) | every 15 s |
| Docker containers | Docker Engine API on the OrbStack socket, `cpu_usage.total_usage` deltas (no `docker` CLI) | every 60 s |
| System memory: pressure level, used / app / wired / compressed / cached / free, swap used and total, swap-in/out and page-out | `host_statistics64` (`vm_statistics64`) and `sysctlbyname` (`vm.swapusage`, `kern.memorystatus_vm_pressure_level`) in process, ~7 µs | every sample |
| Memory per app | summed footprint (`ri_phys_footprint`, Activity Monitor's Memory column) and RSS. Other users' processes can't be read for footprint, so their RSS stands in. | every 60 s |

### Own cost

The budget is 0.5% of one core on average (~75 ms of CPU per 15 s sample).
Each sample records the sampler's own CPU (`getrusage` of itself and its
children) and RSS; `report` and `status` print the average and peak. If the
rolling average over 20 samples (5 min) goes over budget, all intervals stretch ×1.5
(up to ×4) and the log says so; they relax again once it is under 0.2%.
launchd runs it with `ProcessType=Background`, `Nice=10` and `LowPriorityIO`,
which keeps it on the efficiency cores.

CPU is always a delta of cumulative CPU time, never `ps`'s decaying `%cpu`.
Percentages are "% of one core" (Activity Monitor's convention, so 10 cores =
1000%).

### Short-lived processes

- A process first seen at a poll counts from zero only if it started after the
  previous poll (its start time from `proc_pid_rusage`, or `etime` from `ps`);
  one that was already running is baselined, so its lifetime CPU is never
  counted as one sample's usage.
- Processes that start and exit between polls are caught through their parent:
  the parent's reaped-children time (`ri_child_user/system_time`) grows by their
  CPU. Whatever growth is not explained by children the sampler saw is credited
  to the parent's app as a row named `(children of <parent>)`. This is how
  bursts like a test runner spawning hundreds of `git` / `xcrun` / `simctl`
  calls show up.
- Those children ran inside the poll interval, so together they are capped at
  the machine's busy CPU for that interval minus the per-PID deltas. A bigger
  jump (the lifetime of a long-lived child that was never tracked, landing in
  its parent's counter when it exits) is scaled down and logged.
- Each sample also holds attributed CPU to the machine counter (with one
  sample of carry-over, since polls and samples are not aligned) and caps any
  app at cores x sample length. The report flags samples that still attribute
  clearly more than the machine used.
- `usagemon.py repair [--since today] [--dry-run]` trims such rows written by
  older builds (children rows first, then the whole sample, down to the
  machine's CPU), backs up the database first and rebuilds the hourly rollups.
- `unattributed` in the summary is machine CPU minus everything attributed:
  kernel work, other users' processes that live under 30 s, and rounding.
- Apps under 0.05 cpu-s in a sample are summed into one `(other)` row.

### Grouping into apps

- An executable inside a `.app` bundle counts toward the outermost bundle
  (`Claude Helper (GPU)` → `Claude`, `Google Chrome Helper` → `Google Chrome`).
  Exception: `Xcode.app/Contents/Developer/Applications/Simulator.app` → `Simulator`.
- iOS Simulator app processes → `Simulator: <AppName>`; everything else under
  CoreSimulator (launchd_sim, SpringBoard, SimMetalHost…) → `iOS Simulator runtime`.
- Command-line tools use the executable name. Interpreters (node, python, bun,
  sh, bash, zsh…) add a hint from their arguments: `claude-agent-sdk`,
  `node --test`, `node <npm package>`, `bash test-flows.sh`.
- `via` is the nearest ancestor that is a `.app` (for example a CLI started from
  `WezTerm` or `Claude`), when one exists.

## Tables

- `samples`: one row per 15 s sample: machine CPU, attributed CPU, GPU %, the sampler's own CPU and RSS.
- `app_cpu`: per app per sample (≥ 0.05 cpu-s or GPU-s; the rest in `(other)`). Each sample is one transaction (WAL).
- `proc_cpu`: per process per sample (rows with ≥ 0.1 cpu-s), for drilling into spikes.
- `docker`: as above.
- `mem`: per app every 60 s: footprint, RSS and process count (apps under 20 MB in `(other)`).
- `sysmem`: machine memory every sample, in MB; swap-in/out and page-out are the MB moved since the previous sample.
- `hourly_app`, `hourly_sys`, `hourly_docker`, `hourly_sysmem`, `hourly_mem`: hourly rollups, rebuilt each hour.

Raw rows are kept 30 days, rollups 400 days. Reports over windows older than
30 days read the rollups.

## Report sections

`--sections top,procs,hourly,docker,gpu,mem,spikes` (default all):

- `top`: apps by CPU-seconds, with average % of one core, share of machine CPU and GPU-seconds.
- `procs`: individual process names within apps.
- `hourly`: CPU and GPU per hour with the top three apps.
- `docker`: containers by CPU-seconds and memory.
- `gpu`: Device-utilisation timeline (1 min / 5 min / 1 h buckets by window) with the apps using GPU time, and top apps by GPU time.
- `mem`: a machine summary (used, peak pressure, compressed, swap, swapped out,
  lowest free), apps by average and peak footprint (an app missing from a
  snapshot counts as 0 in the average), and a timeline of pressure, used,
  compressed, swap, free and swap-outs with the two largest apps per bucket.
- `spikes`: runs of consecutive samples where one app stayed above
  `--spike-pct` (default 100% = one core), ranked by CPU-seconds, with the
  app's median over the previous hour as a baseline.

`--format json` or `--format csv` dump the same sections.
