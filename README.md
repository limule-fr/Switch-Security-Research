# Switch Security Research

Read-only Nintendo Switch information collector with a portable C++17 core.
The PC executable is a development/test harness; it is not a firmware
analyzer. Horizon-only system queries and SD mounting are isolated in the
platform adapter.

## Layout

```text
.
├── Makefile
├── README.md
├── app/main.cpp
├── include/switchscan/
│   ├── check.hpp
│   ├── inventory.hpp
│   ├── json_exporter.hpp
│   ├── logger.hpp
│   ├── platform.hpp
│   ├── qr_code.hpp        # legacy utility, not used by report generation
│   ├── report.hpp
│   ├── scan_engine.hpp
│   ├── sha256.hpp
│   ├── system_info.hpp
│   └── types.hpp
├── src/
│   ├── inventory.cpp
│   ├── json_exporter.cpp
│   ├── logger.cpp
│   ├── platform_horizon.cpp
│   ├── platform_pc.cpp
│   ├── qr_code.cpp        # not included in the collector build
│   ├── report.cpp
│   ├── scan_engine.cpp
│   ├── sha256.cpp
│   ├── system_info.cpp
│   └── types.cpp
└── tests/test_scan_engine.cpp
```

## Collector scope and safety

- On Horizon, the collector asks `set:sys` for firmware and model and mounts
  only `sdmc:`. Every service or file access can fail; those results are kept
  as `NOT_ACCESSIBLE`, not represented as a clean scan.
- The NRO reports only the running OS version returned by `set:sys`. It does
  not inspect the SYSTEM partition or report an installed-image version.
- The Switch build scans only
  `sdmc:/switch/SwitchSecurityResearch/input/`. It does not enumerate NAND,
  system partitions, other processes, other titles' save data, or files outside
  that directory. Symbolic links are not followed. Each file is read in
  32-KiB chunks, with limits of 64 MiB per file, 1000 entries, and eight
  directory levels.
- The reference manifest is optional and read-only at
  `sdmc:/switch/SwitchSecurityResearch/references.sha256`. Each line is
  `<sha256> <relative/path>`. A difference is reported as an integrity
  discrepancy (`SUSPECT`), never by itself as a confirmed vulnerability.
  Without a reference, a calculated hash has status `UNKNOWN` rather than
  “clean”.
- JSON reports are written only under `sdmc:/rapports_SSR/`. The report path is
  separate from the input directory. A temporary file is finalized by rename
  after the JSON has been written and closed successfully; the NRO checks that
  the target path is absent before rename. Collision behavior during a
  concurrent write still requires validation against Horizon's filesystem.
- Reports identify the collector and version, distinguish `RUNNING_OS` from
  `INSTALLED_IMAGE`, and include checks, inaccessible resources, and errors.
  `INSTALLED_IMAGE` remains `NOT_ACCESSIBLE` for the NRO. No confidence
  percentage is emitted because no confidence methodology is defined.
- `VULNERABLE` is retained only when a check supplies explicit sufficient
  evidence. A hash mismatch is reported as `SUSPECT`, never as a confirmed
  vulnerability. Inaccessible resources are not treated as safe or vulnerable.
- QR output is not part of report generation. JSON is the required, standalone
  report format.

The PC test adapter marks Horizon-specific data as unavailable. PC inventory
uses the selected host directory and the same bounds, hashing, manifest
comparison, and JSON schema. Its report type is `PC_TEST`, not `NRO`.

## PC build, test, and run

```sh
make pc
make test
```

Run against a chosen directory; the manifest is optional. A JSON test report is
written to the specified output:

```sh
mkdir -p build/sample
printf 'sample\n' > build/sample/example.txt
./build/switch_security_research \
  --root build/sample \
  --references build/scan-references.sha256 \
  --output build/scan-report.json
```

The report includes the report ID and collector type `PC_TEST`. Logs go to
standard error. Missing or invalid references are recorded in the report; they
do not stop collection.

## Nintendo Switch build

With devkitPro, devkitA64, and libnx installed:

```sh
make switch
```

This builds `build/switch_security_research.nro`. On launch, the collector
attempts the scoped input path and creates `sdmc:/rapports_SSR/` if needed.
Reports are named `report-<report_id>.json`; existing files are not replaced.
If SD mounting or report writing fails, the program reports the error and does
not claim that a report was saved. Actual firmware/service availability depends
on the homebrew launch context; the configured target 23.0.1 is not assumed to
be the runtime version.

## License

This project is licensed under the GNU General Public License
version 2 or (at your option) any later version.

See [LICENSE](LICENSE) for details.