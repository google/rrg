// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! Extensions to the standard [`std::alloc`] module.

/// RAII-enabled wrapper around global allocations.
///
/// Sometimes the standard [`std::alloc`] functions are quite cumbersome to use,
/// especially when it comes to error handling. This is because that they are
/// defined with performance in mind and put as much burden as possible on the
/// programmer.
///
/// However, in situations when squeezing every cycle out of CPU is not needed,
/// this wrapper that checks many of the invariants at runtime and correctly
/// manages allocation lifecycle can be very helpful.
pub struct Allocation {
    /// The layout used for this allocation.
    layout: std::alloc::Layout,
    /// Pointer to the buffer of this allocation.
    ptr: std::ptr::NonNull<u8>,
}

impl Allocation {

    /// Allocate memory as described by the given `layout`.
    ///
    /// Returns `None` if the allocation failed.
    ///
    /// See documentation of the standard [`std::alloc::alloc`] function for
    /// more information.
    ///
    /// # Panics
    ///
    /// This function panics if `layout` does not have a positive size.
    #[inline]
    pub fn new(layout: std::alloc::Layout) -> Option<Allocation> {
        assert!(layout.size() > 0);

        // SAFETY: We ensure that the layout has a non-zero size above, which is
        // the only safety requirement for calling `alloc`.
        let ptr = unsafe {
            std::alloc::alloc(layout)
        };

        Some(Allocation {
            layout,
            ptr: std::ptr::NonNull::new(ptr)?,
        })
    }

    /// Shrink or grow the allocation to the given `new_size`.
    ///
    /// Returns an `Ok` with a new allocation if the operation succeeded or an
    /// `Err` with the old allocation if it failed.
    ///
    /// # Panics
    ///
    /// This function will panic if the new size is not positive or if it
    /// overflows when rounded to the original alignment.
    #[inline]
    pub fn resize(mut self, new_size: usize) -> Result<Allocation, Allocation> {
        assert!(new_size > 0);

        let new_layout = std::alloc::Layout::from_size_align(
            new_size,
            self.layout.align(),
        ).unwrap();

        // SAFETY: There are multiple requirements for the `realloc` call to be
        // safe.
        //
        // The first one is to ensure that the pointer we reallocate has been
        // allocated with the same allocator which is trivially true as we only
        // use the global one.
        //
        // The second one is to ensure that we pass the same layout that we used
        // to allocate the block of memory, which is also true as we keep the
        // layout around in the struct.
        //
        // Finally, we need to ensure that `new_size` is greater than zero and
        // that it does not overflow when rounded up to the alignment. The first
        // part is ensured by our assertion whereas the second part is ensured
        // by the `from_size_align` call which returns an error if the condition
        // is not met.
        let ptr = unsafe {
            std::alloc::realloc(self.ptr.as_ptr(), self.layout, new_size)
        };

        // In case `realloc` returns a non-null pointer, the old pointer is no
        // longer usable and should be forgotten. In case rallocation fails, the
        // old pointer is still valid so we return it as an "error" case (the
        // caller is free to call `.unwrap()` on it which will call `drop` on it
        // automatically releasing the memory.
        match std::ptr::NonNull::new(ptr) {
            Some(ptr) => {
                self.ptr = ptr;
                self.layout = new_layout;
                Ok(self)
            }
            None => Err(self),
        }
    }

    /// Acquires the pointer to the memory owned by this allocation.
    ///
    /// Note that the memory pointed by it might or might not be initialized. It
    /// is up to the caller to ensure the safety of using this pointer.
    pub fn as_ptr(&self) -> std::ptr::NonNull<u8> {
        self.ptr
    }
}

impl Drop for Allocation {

    #[inline]
    fn drop(&mut self) {
        // SAFETY: There are two requirements for the `dealloc` call to be safe.
        //
        // The first one is to ensure that the pointer we deallocate has been
        // allocated with the same allocator which is trivially true as we only
        // use the global one.
        //
        // The second one is to ensure that it is the same layout that we used
        // to allocate the block of memory, which is also true as we keep the
        // layout around in the struct.
        unsafe {
            std::alloc::dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}
