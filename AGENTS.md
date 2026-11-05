# mac-usage-monitor

Background CPU, GPU and memory usage logger for a Mac, plus a report
command. Everything is in `usagemon.py` (PEP 723 script run with `uv`, standard
library only). `README.md` explains installing on a new Mac, sampling,
attribution, the tables and the report sections.

- Installed as the launchd user agent `local.mac-usage-monitor`
  (`./usagemon.py install` / `uninstall` / `status`). It needs `uv` on the PATH
  and no admin rights. The plist points at this folder, so after editing
  `usagemon.py` or moving the folder, run `./usagemon.py install` again to
  restart the agent.
- Database: `~/Library/Application Support/mac-usage-monitor/usage.db`; log:
  `~/Library/Logs/mac-usage-monitor.log`. Test against a scratch copy with
  `USAGEMON_DB=/path/test.db ./usagemon.py run`.
- Keep the sampler cheap: its own CPU budget is 0.5% of one core (rolling
  average; it stretches its intervals when over and logs it). Check
  `./usagemon.py status` after any change to the sampling loop. Prefer
  in-process reads (libproc, IOKit, sysctl via ctypes) to starting a process
  per sample.
- Attributed CPU must never exceed the machine's busy CPU. Rows written by an
  older build that do can be trimmed with `./usagemon.py repair --since ...`
  (`--dry-run` first; it backs up the database and rebuilds the rollups).
- Answering "what used CPU/GPU/memory at time X":
  `./usagemon.py report --since ... --until ...`, then
  `--sections procs,spikes --app NAME` or `--sections mem` to drill in, or
  query the SQLite tables.
