# ARM32 interpreter microbenchmark

CI builds and runs `retrobridge_arm32_benchmark` in the optimized host `RelWithDebInfo` configuration. It maps an eight-byte guest program containing an A32 `ADD r0, r0, #1` and a backward branch, executes a 100,000-instruction warm-up, then runs five measured samples at a two-million guest-instruction budget. Each sample must end with `BudgetExhausted`, report the exact instruction count, and produce the expected register result; otherwise the benchmark exits nonzero and CI fails.

The median sample is reported as elapsed nanoseconds, nanoseconds per guest instruction, and guest instructions per second. CI writes the JSON result to `diagnostics/arm32-interpreter-benchmark.json` and uploads it as an artifact. The benchmark is informational: it has no speed threshold because shared GitHub runners vary. The instruction loop measures only a synthetic host-side A32 arithmetic/branch path. It does not measure Android devices, APK parsing, ELF loading, Bionic, framework calls, graphics/audio, or an imported application's performance.

Run it from a configured native host build directory with:

```sh
retrobridge_arm32_benchmark [guest-instructions]
```

The optional count is bounded from 10,000 to 50,000,000; the default is 2,000,000. Local toolchain builds are not required for this project; the supported benchmark/build result is produced by GitHub Actions.
