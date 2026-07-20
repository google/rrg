Contributing
============

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement (CLA). You (or your employer) retain the copyright to your
contribution; this simply gives us permission to use and redistribute your
contributions as part of the project. Head over to
<https://cla.developers.google.com/> to see your current agreements on file or
to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Style guide

This project follows the official Rust [style guidelines][rust-style] and all
code should be written with them in mind. Using tools such as [Clippy][clippy]
and [Rustfmt][rustfmt] can be very helpful with this.

[rust-style]: https://doc.rust-lang.org/1.0.0/style/
[clippy]: https://github.com/rust-lang/rust-clippy
[rustfmt]: https://github.com/rust-lang/rustfmt

## Code reviews

In order to submit new code to this repository a code review is needed. Follow
the [GitHub Help][github-pr] guide to learn about the pull request process.

[github-pr]: https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests

## Commit messages

Commit messages should fit the 50 character limit (and since they should map 1:1
to pull request titles, the same applies to these).

Each commit message should be properly capitalized and start with a verb (e.g.
_Add_, _Fix_, _Refactor_, _Implement_, _Improve_) using imperative style (so,
you should **not** use forms like _Adding_ or _Adds_).

It is fine to not follow this convention in your local repository as commits
are going to be squashed into a single commit using pull request title as the
message. Do note though that your pull request title might be edited to fit
this style before it gets merged.
