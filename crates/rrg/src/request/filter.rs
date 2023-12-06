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
    /// The variable denoted by 
    var: Vec<u32>,
    /// The operator to apply.
    op: CondOp,
    /// Determines whether the operator result should be negated.
    negated: bool,
}

/// Individual condition operator of the filter of the form _⋄ l_.
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
        let mut result = false;
 
        for cond in &self.conds {
            result |= cond.eval_message(message)?;
        }

        Ok(result)
    }
}

impl Cond {

    /// Verifies whether the given message passes the condition.
    /// 
    /// The message passes the condition if the condition operator applied to
    /// the value of the condition field within the message.
    fn eval_message(
        &self,
        message: &dyn protobuf::MessageDyn,
    ) -> Result<bool, Error> {
        let Some((head_num, tail_nums)) = self.var.split_first() else {
            return Err(Error);
        };

        self.eval_message_at(message, *head_num, tail_nums)
    }

    /// Verifies whether the message at certain field passes the condition.
    /// 
    /// The message passes the condition if the condition operator applied to
    /// the value of the field within the message denoted by `head_num` and
    /// `tail_nums`.
    /// 
    /// `head_num` stands for the field number of `message` with `tail_nums`
    /// referring to submessages within it.
    fn eval_message_at(
        &self,
        message: &dyn protobuf::MessageDyn,
        head_num: u32,
        tail_nums: &[u32],
    ) -> Result<bool, Error> {
        let field_desc = message.descriptor_dyn().field_by_number(head_num)
            .ok_or(Error)?;

        // We only support singular fields. The call below could panic if not
        // for this check.
        if !field_desc.is_singular() {
            return Err(Error);
        }

        let field = field_desc.get_singular_field_or_default(message);

        match tail_nums.split_first() {
            None => self.eval_value(field),
            Some((new_head_num, new_tail_nums)) => {
                let ReflectValueRef::Message(message) = field else {
                    return Err(Error);
                };

                self.eval_message_at(&*message, *new_head_num, new_tail_nums)
            }
        }
    }

    /// Verifies whether the given value passes the condition.
    ///
    /// The value passes the condition if the condition operator applied to it
    /// evaluates to `true`.
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
