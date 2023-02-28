// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Traits for conversions between types.
//!
//! This module provides utility traits similar to what `std::convert` does and
//! can be thought as an extension of it to fit RRG-specific purposes.

/// A lossy conversion from one type to the other.
///
/// This trait is very similar to `From` from the standard library, except that
/// it allows values to lose some information. Moreover, the implementers are
/// allowed to log details about the lost information, so the conversion might
/// have side effects.
///
/// See also [`IntoLossy`].
///
/// [`IntoLossy`]: trait.IntoLossy.html
pub trait FromLossy<T>: Sized {
    /// Convert the value of another type.
    fn from_lossy(_: T) -> Self;
}

/// A lossy conversion into one type from the other.
///
/// This trait is very similar to `Into` from the standard library, except that
/// it allows values to lose some information. Moreover, the implementers are
/// allowed to log details about the lost information, so the conversion might
/// have side effects.
///
/// Note that it is discouraged to implement this trait directly. Instead, one
/// should provide a reverse implementation for [`FromLossy`] and derive the
/// implementation for `IntoLossy` automatically.
///
/// [`FromLossy`]: trait.FromLossy.html
pub trait IntoLossy<T>: Sized {
    /// Convert the value into another type.
    fn into_lossy(self) -> T;
}

impl<T, U> IntoLossy<U> for T
where
    U: FromLossy<T>,
{

    fn into_lossy(self) -> U {
        U::from_lossy(self)
    }
}
