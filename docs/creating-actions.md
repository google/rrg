Creating actions
================

Creating new actions is easy but requires some boilerplate to be written first.
You can take a look at commit [`845c87b`] to see an example of that. Follow the
steps outlined in this guide for more details.

### Define Protocol Buffers messages

Each action should define its arguments and result as Protocol Buffer messages
in its own package using the `proto3` syntax. All `.proto` definitions live in
the `proto/rrg/action` subfolder. The file (and package) should be named as the
action it corresponds to and should contain at least two messages named `Args`
and `Result` and have an appropriate license header.

For example, when implementing an action called `list_foo`, you should create
a `proto/rrg/action/list_foo.proto` file that looks like this:

    // Copyright 2023 Google LLC
    //
    // Use of this source code is governed by an MIT-style license that can be found
    // in the LICENSE file or at https://opensource.org/licenses/MIT.
    syntax = "proto3";

    package rrg.action.list_foo;

    message Args {
      // TODO.
    }

    message Result {
      // TODO.
    }

The path to the created file needs to be added to the [build script][1] of the
`rrg-proto` crate.

### Define a Cargo feature

Every action needs to be hidden behind a feature. This way actions that are
irrelevant for specific deployments can be completely compiled-out from the
agent executable making it smaller and potentially more secure.

Action features are defined in the [Cargo manifest][2] of the main `rrg` crate
and should use `action-` prefix. For example, a feature flag for the `list_foo`
action would be named `action-list_foo`. You can also add the feature to the
list of default features, if it makes sense for your action.

If your action needs some third-party dependencies that are specific to it, make
them optional and use feature dependencies to specify them, e.g.:

    action-list_foo = ["dep:bar", "dep:baz"]

    (...)

    [dependencies.bar]
    version = "1.33.7"
    optional = true

    [dependencies.baz]
    version = "0.42.0"
    optional = true

### Create a Rust module

All actions should be defined in their own modules as children of the parent
[`rrg::action`] module and be named the same as the action itself. This module
should define idiomatic Rust types corresponding to the argument and result
messages defined in the `.proto` file. Unfortunately, because `Result` is an
already established concept in Rust, the type corresponding to the `Result`
message has to be named differently—in Rust code we use `Item` instead. These
types should implement `rrg::request::Args` and `rrg::request::Item` traits to
convert between idiomatic Rust and Protocol Buffers types. Finally, the module
should implement a `handle` method that executes the action.

For example, when implementing an action called `list_foo`, you should create
a `crates/rrg/src/action/list_foo.rs` file that looks like this:

    // Copyright 2023 Google LLC
    //
    // Use of this source code is governed by an MIT-style license that can be found
    // in the LICENSE file or at https://opensource.org/licenses/MIT.

    /// Arguments of the `list_foo` action.
    pub struct Args {
        // TODO.
    }

    /// Result of the `list_foo` action.
    pub struct Item {
        // TODO.
    }

    /// Handles invocations of the `list_foo` action.
    pub fn handle<S>(session: &mut S, args: Args) -> crate::session::Result<()>
    where
        S: crate::session::Session,
    {
        todo!()
    }

    impl crate::request::Args for Args {

        type Proto = rrg_proto::list_foo::Args;

        fn from_proto(mut proto: Self::Proto) -> Result<Args, crate::request::ParseArgsError> {
            todo!()
        }
    }

    impl crate::response::Item for Item {

        type Proto = rrg_proto::list_foo::Result;

        fn into_proto(self) -> Self::Proto {
            todo!()
        }
    }

This file has to be declared as a child of the [`rrg::action`] module and should
be hidden behind the feature declared earlier:

    #[cfg(feature = "action-list_foo")]
    pub mod list_foo;

### Register the action

Finally, the action has to be registered so that requests can actually be routed
to invoke it.

First, you need to extend the [RRG protocol][3]. Add the new variant to the
`Action` enum that has the same name as the action. If you are contributing
upstream, pick and use the first available field number. If you are developing
an action that is internal to your deployment, use one of the field numbers from
the reserved range between 1024 and 2048.

Once the Protocol Buffers enum has the new field, add a new variant to the Rust
`Action` enum defined in the [`rrg::request`] module. The compiler and the tests
will guide you to towards updating the existing code to cover the new variant in
all the required branches.

As the last step, update the `dispatch` function in the [`rrg::request`] module
and route the call to the `handle` function you defined. Remember to guard the
branch with the corresponding feature to avoid issues when compiling with the
feature disabled. 


[1]: https://github.com/google/rrg/blob/master/crates/rrg-proto/build.rs
[2]: https://github.com/google/rrg/blob/master/crates/rrg/Cargo.toml
[3]: https://github.com/google/rrg/blob/master/proto/rrg.proto

[`rrg::action`]: https://github.com/google/rrg/blob/master/crates/rrg/src/action.rs
[`rrg::request`]: https://github.com/google/rrg/blob/master/crates/rrg/src/request.rs

[`845c87b`]: https://github.com/google/rrg/commit/845c87b7c3373abacf41a17729ad95e1d6ab046a
