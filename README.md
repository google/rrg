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
