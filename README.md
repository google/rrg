RRG
===

[![CI status][ci-badge]][ci]

RRG is a *[Rust][rust] rewrite of [GRR][grr]* (a remote live forensics
framework).

It strives to evaluate how feasible it is to rewrite the client-side part of GRR
(an agent service) without all the historical baggage that the current version
has to carry. For example, it does not implement its own communication layer,
but leverages [Fleetspeak][fleetspeak] for that. It also tries to assess how
many existing issues related to the Python codebase could be resolved by using a
modern language with powerful type system and strong safety guarantees.

This project is not an official Google product, is under heavy development and
should not be used for any production deployments. So far, it is nothing more
than an experiment.

[rust]: https://rust-lang.org
[grr]: https://github.com/google/grr
[fleetspeak]: https://github.com/google/fleetspeak

[ci]: https://github.com/google/rrg/actions?query=workflow%3AIntegrate
[ci-badge]: https://github.com/google/rrg/workflows/Integrate/badge.svg

Development
-----------

### Prerequisites

RRG is written in Rust and needs a Rust toolchain to be built. The recommended
way of installing Rust is to use [rustup](https://rustup.rs/).

Because RRG is only a component of a bigger system, to do anything useful with
it you also need to [setup Fleetspeak][fleetspeak-guide] and [GRR][grr-guide].

[fleetspeak-guide]: https://github.com/google/fleetspeak/blob/master/docs/guide.md
[grr-guide]: https://grr-doc.readthedocs.io/en/latest/fleetspeak/from-source.html

### Building

RRG uses Cargo for everything, so building it is as easy as running:

    $ cargo build

This will create a unoptimized executable `target/debug/rrg`.

To create release executable (note that this is much slower and is not suitable
for quick iterations) run:

    $ cargo build --release

This will create an optimized executable `target/release/rrg`.

### Testing

To run all tests:

    $ cargo test

To run tests only for a particular crate:

    $ cargo test --package='ospect'

To run only a particular test:

    $ cargo test --package='rrg' action::get_file_contents::tests::handle_empty_file

To verify that the code compiles on all supported platforms:

    $ cargo check --tests --target='x86_64-unknown-linux-gnu' --target='x86_64-apple-darwin' --target='x86_64-pc-windows-gnu'

Note that this requires additional toolchains for cross-compilation to be
[installed](https://rust-lang.github.io/rustup/cross-compilation.html).

It is also possible to use cross-compilation and tools like Wine to run tests
on another operating system:

    $ cargo test --target='x86_64-pc-windows-gnu' --package='rrg' --no-run
    $ wine target/x86_64-pc-windows-gnu/debug/deps/rrg-bcf99adf861ea84a.exe

Structure
---------

### Directories

  * `crates/` — All Rust crates that the project consists of live here.
  * `proto/` — All Protocol Buffers definitions describing RRG's API live here.

### Crates

  * `ospect` — Tools for inspecting the operating system.
  * `rrg` — Implementation of all agent actions and the entry point.
  * `rrg-proto` — Code generated from Protocol Buffer definitions.
