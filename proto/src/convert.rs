// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

pub trait FromLossy<T>: Sized {
    fn from_lossy(_: T) -> Self;
}

pub trait IntoLossy<T>: Sized {
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
