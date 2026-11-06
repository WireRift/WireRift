# Capacity Benchmarking

WireRift's benchmark is an in-process single-node capacity baseline. It starts a
real server, client, HTTP upstream, HTTP tunnel, and TCP tunnel on loopback. It
is not a substitute for staging tests across a real network.

## Correctness contract

- Every setup, transport, body-copy, and tunnel-creation error is fatal.
- Only 2xx responses count toward request throughput. A rate-limit or server
  error invalidates the run instead of inflating requests per second.
- The server's production abuse limit stays enabled. Requests use a bounded pool
  of 4,096 RFC 2544 visitor addresses through an explicitly trusted loopback
  proxy boundary, modelling many visitors without unbounded limiter state.
- Direct and tunneled latency use the same local upstream. Reported overhead is
  tunneled p95 minus direct p95, floored at zero. Tunnel setup also reports p95
  and p99 rather than hiding tail latency behind a batch average.
- Full runs use 1,000 health samples, 100 samples per payload, three-second
  throughput/concurrency windows, concurrency 1/10/50, and 50 tunnel creations.
  `WIRERIFT_BENCH_QUICK=1` is only a short integrity smoke used by CI.

## Running a controlled baseline

Record the commit, CPU model, kernel, container runtime, Go version, CPU quota,
memory limit, and whether the host was otherwise idle. Pin the runner image by
digest in the actual capacity environment.

```bash
docker run --rm \
  --cpus 2 --memory 1g --pids-limit 512 \
  -v "$PWD:/src" -w /src \
  golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb \
  go run ./test/benchmark/
```

Run at least five times after a warm-up and retain every result, not only the
best. Compare medians and tail latency on identical runner classes. Shared CI
only checks measurement integrity because noisy hosted runners are unsuitable
for performance regression thresholds.

## Target coverage

The suite directly measures tunnel establishment, HTTP tunnel overhead, HTTP
upload/download throughput, successful request throughput, and TCP throughput.
The separate capacity command validates concurrent-stream, idle-tunnel, and
live-heap-per-idle-tunnel targets. CI runs a small harness smoke; the release
profile must run with the full defaults on the controlled runner:

```bash
docker run --rm --cpus 2 --memory 1g --pids-limit 512 \
  -v "$PWD:/src" -w /src \
  golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb \
  go run ./test/capacity/ -profile all
```

This creates 257 simultaneous mux streams and 10,000 idle HTTP tunnels across
1,000 authenticated sessions, and fails at >=50 KiB of additional live heap per
idle tunnel. Cold-start and binary-size targets remain separate release checks.
Capacity profiles are release evidence, not per-commit hosted-CI gates.

The included Compose defaults (2 CPUs, 1 GiB memory, 512 PIDs) are the initial
single-node envelope validated by this profile. Override `WIRERIFT_CPUS`,
`WIRERIFT_MEMORY_LIMIT`, or `WIRERIFT_PIDS_LIMIT` only after repeating the full
profile and staging soak at the proposed values; the deployment preflight
rejects zero/unlimited values.

## Result record

Store controlled results with the release evidence using this header:

```text
commit=<full SHA>  dirty=<true|false>  date=<UTC ISO-8601>
go=<version>  os=<kernel>  arch=<architecture>  cpu=<model>
cpus=<quota>  memory=<limit>  pids=<limit>  runner=<identifier>
warmups=<count>  measured_runs=<count>
```

Do not update product claims from one laptop or one run. Capacity-derived
container limits require the controlled profiles above plus staging soak data.
