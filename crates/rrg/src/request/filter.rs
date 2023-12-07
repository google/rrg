// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use protobuf::reflect::ReflectValueRef;

/// The error type for filter evaluation.
pub struct Error; // TODO(@panhania): Add error details.

/// A filter is a formula of the form _(x₁ ⋄₁ l₁) ∨ ⋯ ∨ (xₙ ⋄ₙ lₙ)_.
///
/// Here, xᵢ means a _variable_ (to be substituted by particular value from the
/// result Protocol Buffers message), ⋄ᵢ is an _operator_ and lᵢ is a _literal_.
/// We will say that a message passes a filter if the evaluation of this logical
/// formula is true. Individual xᵢ ⋄ᵢ lᵢ triplets are called _conditions_.
///
/// Note that the filter is actually a clause (a sequence of disjunctions). In
/// order to model conjunction ("and" behaviour) one can define many filters. In
/// this sense, the filtering mechanism is actually a formula in [conjunctive
/// normal form][1].
//
/// [1]: https://en.wikipedia.org/wiki/Conjunctive_normal_form
pub struct Filter {
    conds: Vec<Cond>,
}

/// Individual condition of the filter of the form _x ⋄ l_.
///
/// See documentation for [`Filter`] for more details.
struct Cond {
    /// The variable to check the condition against.
    var: CondVar,
    /// The operator to apply.
    op: CondFullOp,
}

/// Individual condition variable.
/// 
/// The variable is denoted by a non-empty sequence of message field numbers
/// referring to a primitive value of arbitrary message.
/// 
/// Consider the following Protocol Buffers message definitions:
/// 
/// ```protobuf
/// message Foo {
///   Bar bar = 1;
/// }
/// 
/// message Bar {
///   Quux quux = 1;
///   string thud = 2;
/// }
/// 
/// message Quux {
///   reserved 1;
///   reserved 2;
///   uint32 norf = 3;
/// }
/// ```
/// 
/// Variable `1.3` on `Foo` instance will refer to `bar.thud` of type `string`
/// whereas the same variable on `Bar` instance will refer to field `quux.norf`
/// of type `uint32`.
struct CondVar {
    top_field_num: u32,
    nested_field_nums: Vec<u32>,
}

/// Borrowed reference to an individual condition variable.
/// 
/// This is essentially a non-owned variant of [`CondVar`] that makes working
/// with it easier.
#[derive(Clone, Copy)]
struct CondVarRef<'a> {
    top_field_num: u32,
    nested_field_nums: &'a [u32],
}

/// Individual condition operator of the form _□ ⋄ l_ (including negation).
/// 
/// See documentation for [`Filter`] for more details.
struct CondFullOp {
    /// The basic operator to apply.
    op: CondOp,
    /// Determines whether the operator result should be negated.
    negated: bool,
}

/// Individual basic condition operator of the form _□ ⋄ l_ (without negation.
/// 
/// See documentation for [`Filter`] for more details.
enum CondOp {
    /// Equality check against a [`bool`] value.
    BoolEqual(bool),
    /// Equality check against a [`String`] value.
    StringEqual(String),
    /// Pattern matching against a [`String`] value.
    StringMatch(regex::Regex),
    /// Equality check against a sequence of bytes.
    BytesEqual(Vec<u8>),
    /// Pattern matching against a sequence of bytes.
    BytesMatch(regex::bytes::Regex),
    /// Equality check against a [`u64`] value.
    U64Equal(u64),
    /// Less-than check against a [`u64`] value.
    U64Less(u64),
    /// Equality check against an [`i64`] value.
    I64Equal(i64),
    /// Less-than check against an [`i64`] value.
    I64Less(i64),
}

impl Filter {

    /// Verifies whether the given message passes the filter.
    ///
    /// The message passes the filter if passes any of its conditions.
    fn eval_message(
        &self,
        message: &dyn protobuf::MessageDyn,
    ) -> Result<bool, Error> {
        self.conds.iter().try_fold(false, |acc, cond| Ok({
            acc || cond.eval_message(message)?
        }))
    }
}

impl Cond {

    /// Verifies whether the given message passes the condition.
    fn eval_message(
        &self,
        message: &dyn protobuf::MessageDyn,
    ) -> Result<bool, Error> {
        self.eval_message_at(message, self.var.as_ref())
    }

    /// Verifies whether the message at certain field passes the condition.
    fn eval_message_at(
        &self,
        message: &dyn protobuf::MessageDyn,
        var: CondVarRef<'_>,
    ) -> Result<bool, Error> {
        let message_desc = message.descriptor_dyn();
        let field_desc = message_desc.field_by_number(var.top_field_num)
            .ok_or(Error)?;

        // We only support singular fields. The call below could panic if not
        // for this check.
        if !field_desc.is_singular() {
            return Err(Error);
        }

        let field = field_desc.get_singular_field_or_default(message);

        match var.nested() {
            None => self.op.eval_value(field),
            Some(var) => {
                let ReflectValueRef::Message(message) = field else {
                    return Err(Error);
                };

                self.eval_message_at(&*message, var)
            }
        }
    }
}

impl CondFullOp {

    /// Verifies whether the given value passes the operator.
    /// 
    /// # Errors
    /// 
    /// This function will return an error if the operator cannot be applied
    /// to the given value (e.g. `value` is a string and the operator is boolean
    /// equality)
    fn eval_value(&self, value: ReflectValueRef) -> Result<bool, Error> {
        let mut result = self.op.eval_value(value)?;

        if self.negated {
            result = !result;
        }

        Ok(result)
    }
}

impl CondOp {

    /// Verifies whether the given value passes the operator.
    /// 
    /// # Errors
    /// 
    /// This function will return an error if the operator cannot be applied
    /// to the given value (e.g. `value` is a string and the operator is boolean
    /// equality)
    fn eval_value(&self, value: ReflectValueRef) -> Result<bool, Error> {
        use ReflectValueRef::*;

        match (value, self) {
            (Bool(value), CondOp::BoolEqual(bool)) => {
                Ok(value == *bool)
            }
            (String(value), CondOp::StringEqual(string)) => {
                Ok(value == *string)
            }
            (String(value), CondOp::StringMatch(regex)) => {
                Ok(regex.is_match(value))
            }
            (Bytes(value), CondOp::BytesEqual(bytes)) => {
                Ok(value == *bytes)
            }
            (Bytes(value), CondOp::BytesMatch(regex)) => {
                Ok(regex.is_match(value))
            }
            (U32(value), CondOp::U64Equal(u64)) => {
                Ok(u64::from(value) == *u64)
            }
            (U32(value), CondOp::U64Less(u64)) => {
                Ok(u64::from(value) < *u64)
            }
            (U64(value), CondOp::U64Equal(u64)) => {
                Ok(value == *u64)
            }
            (U64(value), CondOp::U64Less(u64)) => {
                Ok(value < *u64)
            }
            (I32(value), CondOp::I64Equal(i64)) => {
                Ok(i64::from(value) == *i64)
            }
            (I32(value), CondOp::I64Less(i64)) => {
                Ok(i64::from(value) < *i64)
            }
            (I64(value), CondOp::I64Equal(i64)) => {
                Ok(value == *i64)
            }
            (I64(value), CondOp::I64Less(i64)) => {
                Ok(value < *i64)
            }
            (_, _) => Err(Error)
        }
    }
}

impl CondVar {

    /// Converts the variable to its reference wrapper.
    fn as_ref<'a>(&'a self) -> CondVarRef<'a> {
        CondVarRef {
            top_field_num: self.top_field_num,
            nested_field_nums: &self.nested_field_nums,
        }
    }
}

impl<'a> CondVarRef<'a> {

    /// Returns the variable referring to the immediate nested message.
    /// 
    /// In case this variable does not refer to any nested messages, [`None`] is
    /// returned instead.
    fn nested(self) -> Option<CondVarRef<'a>> {
        match self.nested_field_nums.split_first() {
            Some((top_field_num, nested_field_nums)) => Some(CondVarRef {
                top_field_num: *top_field_num,
                nested_field_nums,
            }),
            None => None,
        }
    }
}

impl std::fmt::Display for Filter {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.conds.is_empty() {
            return write!(fmt, "⊥");
        }

        write!(fmt, "{}", self.conds[0])?;
        for cond in &self.conds[1..] {
            write!(fmt, " ∨ {}", cond)?;
        }

        Ok(())
    }
}

impl std::fmt::Display for Cond {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{} {}", self.var, self.op)
    }
}

impl std::fmt::Display for CondVar {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{}", self.as_ref())
    }
}

impl<'a> std::fmt::Display for CondVarRef<'a> {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "𝛸(")?;
        write!(fmt, "{}", self.top_field_num)?;
        for nested_field_num in self.nested_field_nums {
            write!(fmt, ".{}", nested_field_num)?;
        }
        write!(fmt, ")")?;

        Ok(())
    }
}

impl std::fmt::Display for CondFullOp {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.negated {
            use CondOp::*;
            match &self.op {
                BoolEqual(bool) => write!(fmt, "≠ {}", bool),
                StringEqual(string) => write!(fmt, "≠ {:?}", string),
                StringMatch(regex) => write!(fmt, "≄ {:?}", regex.as_str()),
                BytesEqual(bytes) => write!(fmt, "≠ {:?}", bytes),
                BytesMatch(regex) => write!(fmt, "≄ {:?}", regex.as_str()),
                U64Equal(u64) => write!(fmt, "≠ {}", u64),
                U64Less(u64) => write!(fmt, "≮ {}", u64),
                I64Equal(i64) => write!(fmt, "≠ {}", i64),
                I64Less(i64) => write!(fmt, "≮ {}", i64),
            }
        } else {
            write!(fmt, "{}", self.op)
        }
    }
}

impl std::fmt::Display for CondOp {

    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        use CondOp::*;
        match self {
            BoolEqual(bool) => write!(fmt, "= {}", bool),
            StringEqual(string) => write!(fmt, "= {:?}", string),
            StringMatch(regex) => write!(fmt, "≃ {:?}", regex.as_str()),
            BytesEqual(bytes) => write!(fmt, "= {:?}", bytes),
            BytesMatch(regex) => write!(fmt, "≃ {:?}", regex.as_str()),
            U64Equal(u64) => write!(fmt, "= {}", u64),
            U64Less(u64) => write!(fmt, "< {}", u64),
            I64Equal(i64) => write!(fmt, "= {}", i64),
            I64Less(i64) => write!(fmt, "< {}", i64),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    macro_rules! var {
        ($top_field_num:literal) => {
            crate::request::filter::CondVar {
                top_field_num: $top_field_num,
                nested_field_nums: vec![],
            }
        };
        ($top_field_num:literal : $($nested_field_num:literal):*) => {
            crate::request::filter::CondVar {
                top_field_num: $top_field_num,
                nested_field_nums: vec![$($nested_field_num),*],
            }
        };
    }

    macro_rules! op {
        (= true) => {
            crate::request::filter::CondOp::BoolEqual(true)
        };
        (= false) => {
            crate::request::filter::CondOp::BoolEqual(false)
        };
        (= str($val:literal)) => {
            crate::request::filter::CondOp::StringEqual(String::from($val))
        };
        (~= str($val:literal)) => {
            {
                let regex = ::regex::Regex::new($val).unwrap();
                crate::request::filter::CondOp::StringMatch(regex)
            }
        };
        (= bytes($val:literal)) => {
            crate::request::filter::CondOp::BytesEqual($val.to_vec()),
        };
        (~= bytes($val:literal)) => {
            {
                let regex = ::regex::bytes::Regex::new($val).unwrap();
                crate::request::filter::CondOp::BytesMatch(regex)
            }
        };
        (= u64($val:literal)) => {
            crate::request::filter::CondOp::U64Equal($val)
        };
        (< u64($val:literal)) => {
            crate::request::filter::CondOp::U64Less($val)
        };
        (= i64($val:literal)) => {
            crate::request::filter::CondOp::I64Equal($val)
        };
        (< i64($val:literal)) => {
            crate::request::filter::CondOp::I64Less($val)
        };
    }

    macro_rules! cond {
        (not $($cond:tt)*) => {
            {
                let mut cond = cond!($($cond)*);
                cond.op.negated = !cond.op.negated;
                cond
            }
        };
        (var($($var:tt)*) $($op:tt)*) => {
            crate::request::filter::Cond {
                var: var!($($var)*),
                op: crate::request::filter::CondFullOp {
                    op: op!($($op)*),
                    negated: false,
                },
            }
        };
    }

    macro_rules! filter {
        ($($conds:tt)*) => {
            crate::request::filter::Filter {
                conds: vec![$($conds)*],
            }
        }
    }

    #[test]
    fn to_string_filter() {
        assert_eq! {
            filter!().to_string(),
            "⊥"
        };
        assert_eq! {
            filter!(cond!(var(1) = str("foo"))).to_string(),
            "𝛸(1) = \"foo\""
        };
        assert_eq! {
            filter! {
                cond!(var(4:2) < u64(42)),
                cond!(var(1:3:3:7) = str("bar"))
            }.to_string(),
            "𝛸(4.2) < 42 ∨ 𝛸(1.3.3.7) = \"bar\""
        }
    }

    #[test]
    fn to_string_cond() {
        assert_eq! {
            cond!(not var(1:3:3:7) = str("foo")).to_string(),
            "𝛸(1.3.3.7) ≠ \"foo\""
        }
    }

    #[test]
    fn to_string_cond_var() {
        assert_eq!(var!(1).to_string(), "𝛸(1)");
        assert_eq!(var!(4:2).to_string(), "𝛸(4.2)");
        assert_eq!(var!(1:3:3:7).to_string(), "𝛸(1.3.3.7)");
    }

    #[test]
    fn to_string_cond_full_op() {
        assert_eq! {
            cond!(var(0) = true).to_string(),
            "𝛸(0) = true"
        }
        assert_eq! {
            cond!(not var(0) = false).to_string(),
            "𝛸(0) ≠ false",
        }
        assert_eq! {
            cond!(not var(0) = u64(42)).to_string(),
            "𝛸(0) ≠ 42"
        }
        assert_eq! {
            cond!(not var(0) < u64(1337)).to_string(),
            "𝛸(0) ≮ 1337"
        }
    }

    #[test]
    fn to_string_cond_op() {
        assert_eq!(op!(= true).to_string(), "= true");
        assert_eq!(op!(= false).to_string(), "= false");

        assert_eq!(op!(= str("foo")).to_string(), "= \"foo\"");
        assert_eq!(op!(~= str("foo+")).to_string(), "≃ \"foo+\"");

        assert_eq!(op!(= i64(-42)).to_string(), "= -42");
        assert_eq!(op!(< i64(1337)).to_string(), "< 1337");
    }
}
