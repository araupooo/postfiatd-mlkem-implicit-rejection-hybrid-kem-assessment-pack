# Environment

## Run

- **Date**: 2026-11-25 (harness run 15:46 UTC; postfiatd pin verified the same day).
- **Machine**: Linux `htch-runtime`, kernel 7.0.0-44-generic, x86_64.
- **CPU**: AMD EPYC 9D25 126-Core Processor; 4 vCPUs visible, ~1.5 shared CPUs.
- **Memory**: ~6 GB RAM.
- **GPU**: none.
- **OS**: Ubuntu 24.04.
- **Toolchain**: gcc 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), cmake 3.28.3,
  OpenSSL 3.0.13, Python 3.12.3.
- **Harness parameters**: `bench_n=200`, `timing_n=1000`, single-threaded.
  Full harness wall time: 2.3 s.
- **liboqs build**: static library only (`-DOQS_BUILD_ONLY_LIB=ON`,
  `-DOQS_USE_OPENSSL=OFF`, Release), built from source in ~9 minutes on
  this VM.

## Pinned revisions (all verified against the GitHub API on 2026-11-25)

| Component | Revision | Local HEAD | API HEAD | Match |
|---|---|---|---|---|
| postfiatd (`postfiatorg/postfiatd`, `main`) | `0085a1ff885d6a446369cf73a4430f75af22be55` | `0085a1ff885d6a446369cf73a4430f75af22be55` | `0085a1ff885d6a446369cf73a4430f75af22be55` | yes |
| liboqs (tag `0.14.0`) | `94b421ebb82405c843dba4e9aa521a56ee5a333d` | `94b421ebb82405c843dba4e9aa521a56ee5a333d` | `94b421ebb82405c843dba4e9aa521a56ee5a333d` | yes |

postfiatd HEAD is unchanged from the revision pinned by the earlier
assessment work on 2026-11-25; no newer commit exists on `main` as of the
API check. The revision choice (latest `main` HEAD at build time) is
recorded here because no specific revision was named in the assignment.

## Notes for reruns

- Benchmark numbers are wall-clock on shared vCPUs; expect run-to-run
  variation of a few percent and occasional outliers (for example, one
  hybrid encaps sample of 12,021 µs against a 2,315 µs median). Medians
  are the stable comparison figure; means are reported alongside them.
- The harness is deterministic in structure but not in values: keypairs
  are freshly generated per run, so shared-secret digests differ between
  runs. Claims are about counts, return codes, and distinctness, which are
  stable across runs.
