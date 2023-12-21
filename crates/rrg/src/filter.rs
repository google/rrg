// Copyright 2023 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

use protobuf::reflect::ReflectValueRef;

/// Filter set is a formula of the form _𝜑₁ ∧ ⋯ ∧ 𝜑ₙ.
/// 
/// Here, individual 𝜑ᵢ is a [filter][Filter]. Thus, it is essentially a logic
/// formula in [conjunctive normal form][1].
///
/// [1]: https://en.wikipedia.org/wiki/Conjunctive_normal_form
pub struct FilterSet {
    filters: Vec<Filter>,
}

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

impl FilterSet {

    /// Constructs an empty filter set.
    /// 
    /// Every message always passes an empty filter set.
    pub fn empty() -> FilterSet {
        FilterSet {
            filters: Vec::new(),
        }
    }

    /// Verifies whether the given message passes the filter set.
    /// 
    /// The message passes the filter if it passes all filters in the set.
    pub fn eval_message(
        &self,
        message: &dyn protobuf::MessageDyn,
    ) -> Result<bool, Error> {
        self.filters.iter().try_fold(true, |acc, filter| Ok({
            acc && filter.eval_message(message)?
        }))
    }
}

impl Filter {

    /// Verifies whether the given message passes the filter.
    ///
    /// The message passes the filter if passes any of its conditions.
    pub fn eval_message(
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
            .ok_or(ErrorRepr::InvalidFieldNum {
                message_name: message_desc.full_name().to_owned(),
                field_num: var.top_field_num
            })?;

        // We only support singular fields. The call below could panic if not
        // for this check.
        if !field_desc.is_singular() {
            return Err(ErrorRepr::NonSingularField {
                field_name: field_desc.full_name(),
            }.into());
        }

        let field = field_desc.get_singular_field_or_default(message);

        match var.nested() {
            None => self.op.eval_value(field),
            Some(var) => {
                let ReflectValueRef::Message(message) = field else {
                    return Err(ErrorRepr::NonMessageFieldAccess {
                        field_name: field_desc.full_name(),
                    }.into());
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
            (value, _) => Err(ErrorRepr::TypeMismatch {
                var_type: value.get_type(),
                op_type: self.runtime_type(),
            }.into())
        }
    }

    /// Returns the runtime type of values this operator works with.
    fn runtime_type(&self) -> protobuf::reflect::RuntimeType {
        use protobuf::reflect::RuntimeType;
        match self {
            CondOp::BoolEqual(_) => RuntimeType::Bool,
            CondOp::StringEqual(_) => RuntimeType::String,
            CondOp::StringMatch(_) => RuntimeType::String,
            CondOp::BytesEqual(_) => RuntimeType::VecU8,
            CondOp::BytesMatch(_) => RuntimeType::VecU8,
            CondOp::U64Equal(_) => RuntimeType::U64,
            CondOp::U64Less(_) => RuntimeType::U64,
            CondOp::I64Equal(_) => RuntimeType::I64,
            CondOp::I64Less(_) => RuntimeType::I64,
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

/// The error type for filter evaluation.
#[derive(Debug)]
pub struct Error {
    repr: ErrorRepr,
}

/// Internal representation of the error type for filter evaluation.
#[derive(Debug)]
enum ErrorRepr {
    /// Message does not have field of the specified number.
    InvalidFieldNum {
        /// Full name of the message that caused the error.
        message_name: String,
        /// Number of the field that caused the error.
        field_num: u32,
    },
    /// Specified field is not singular (e.g. it has `repeated` annotation).
    NonSingularField {
        /// Full name of the field that caused the error.
        field_name: String,
    },
    /// Specified field is not a message but nested access was attempted.
    NonMessageFieldAccess {
        /// Full name of the field that caused the error.
        field_name: String,
    },
    /// Operator was applied to a value of incorrect type.
    TypeMismatch {
        /// Runtime type of the applied value.
        var_type: protobuf::reflect::RuntimeType,
        /// Runtime type expected by the applied operator.
        op_type: protobuf::reflect::RuntimeType,
    },
}

impl From<ErrorRepr> for Error {

    fn from(error: ErrorRepr) -> Error {
        Error {
            repr: error
        }
    }
}

impl std::fmt::Display for Error {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.repr)
    }
}

impl std::error::Error for Error {
}

impl std::fmt::Display for ErrorRepr {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorRepr::InvalidFieldNum { message_name, field_num } => {
                write!(f, "invalid field number '{field_num}' on `{message_name}`")
            }
            ErrorRepr::NonSingularField { field_name } => {
                write!(f, "non-singular field `{field_name}`")
            }
            ErrorRepr::NonMessageFieldAccess { field_name } => {
                write!(f, "access on non-message field `{field_name}`")
            }
            ErrorRepr::TypeMismatch { var_type, op_type } => {
                write!(f, "comparison of `{var_type}` variable using `{op_type}` operator")
            }
        }
    }
}

impl FromIterator<Filter> for FilterSet {

    fn from_iter<I>(iter: I) -> FilterSet
    where
        I: IntoIterator<Item = Filter>,
    {
        FilterSet {
            filters: iter.into_iter().collect(),
        }
    }
}

impl TryFrom<rrg_proto::rrg::Filter> for Filter {

    type Error = ParseError;

    fn try_from(mut proto: rrg_proto::rrg::Filter) -> Result<Filter, ParseError> {
        let conds = proto.take_conditions().into_iter()
            .map(|cond| Cond::try_from(cond))
            .collect::<Result<_, ParseError>>()?;

        Ok(Filter {
            conds,
        })
    }
}

impl TryFrom<rrg_proto::rrg::Condition> for Cond {

    type Error = ParseError;

    fn try_from(mut proto: rrg_proto::rrg::Condition) -> Result<Cond, ParseError> {
        let mut field_nums = proto.take_field();
        if field_nums.is_empty() {
            return Err(ParseErrorRepr::NoField.into());
        }

        let top_field_num = field_nums[0];
        field_nums.remove(0);

        let var = CondVar {
            top_field_num,
            nested_field_nums: field_nums,
        };

        let op = match () {
            () if proto.has_bool_equal() => {
                CondOp::BoolEqual(proto.bool_equal())
            }
            () if proto.has_string_equal() => {
                CondOp::StringEqual(proto.take_string_equal())
            }
            () if proto.has_string_match() => {
                let regex = regex::Regex::new(proto.string_match())
                    .map_err(ParseErrorRepr::InvalidStringMatchRegex)?;

                CondOp::StringMatch(regex)
            }
            () if proto.has_bytes_match() => {
                CondOp::BytesEqual(proto.take_bytes_equal())
            }
            () if proto.has_bytes_match() => {
                let regex = regex::bytes::Regex::new(proto.bytes_match())
                    .map_err(ParseErrorRepr::InvalidBytesMatchRegex)?;

                CondOp::BytesMatch(regex)
            }
            () if proto.has_uint64_equal() => {
                CondOp::U64Equal(proto.uint64_equal())
            }
            () if proto.has_uint64_less() => {
                CondOp::U64Less(proto.uint64_less())
            }
            () if proto.has_int64_equal() => {
                CondOp::I64Equal(proto.int64_equal())
            }
            () if proto.has_int64_less() => {
                CondOp::I64Less(proto.int64_less())
            }
            () => return Err(ParseErrorRepr::NoOperator.into()),
        };

        Ok(Cond {
            var,
            op: CondFullOp {
                op,
                negated: proto.negated(),
            }
        })
    }
}

/// The error type for parsing filters from Protocol Buffer messages.
#[derive(Debug)]
pub struct ParseError {
    repr: ParseErrorRepr,
}

/// Internal representation of the error type for parsing filters.
#[derive(Debug)]
enum ParseErrorRepr {
    /// Condition has no variable field specified.
    NoField,
    /// Condition has no operator specified.
    NoOperator,
    /// Regex in a string match operator is invalid.
    InvalidStringMatchRegex(regex::Error),
    /// Regex in a bytes match operator is invalid.
    InvalidBytesMatchRegex(regex::Error),
}

impl From<ParseErrorRepr> for ParseError {

    fn from(error: ParseErrorRepr) -> ParseError {
        ParseError {
            repr: error,
        }
    }
}

impl std::fmt::Display for ParseError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.repr)
    }
}

impl std::error::Error for ParseError {

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.repr {
            ParseErrorRepr::NoField => None,
            ParseErrorRepr::NoOperator => None,
            ParseErrorRepr::InvalidStringMatchRegex(ref error) => Some(error),
            ParseErrorRepr::InvalidBytesMatchRegex(ref error) => Some(error),
        }
    }
}

impl std::fmt::Display for ParseErrorRepr {
    
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseErrorRepr::InvalidStringMatchRegex(error) => {
                write!(f, "invalid string match regex: {error}")
            }
            ParseErrorRepr::InvalidBytesMatchRegex(error) => {
                write!(f, "invalid bytes match regex: {error}")
            }
            ParseErrorRepr::NoOperator => {
                write!(f, "no operator")
            }
            ParseErrorRepr::NoField => {
                write!(f, "no field")
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    macro_rules! var {
        ($top_field_num:literal) => {
            crate::filter::CondVar {
                top_field_num: $top_field_num,
                nested_field_nums: vec![],
            }
        };
        ($top_field_num:literal : $($nested_field_num:literal):*) => {
            crate::filter::CondVar {
                top_field_num: $top_field_num,
                nested_field_nums: vec![$($nested_field_num),*],
            }
        };
    }

    macro_rules! op {
        (= true) => {
            crate::filter::CondOp::BoolEqual(true)
        };
        (= false) => {
            crate::filter::CondOp::BoolEqual(false)
        };
        (= str($val:literal)) => {
            crate::filter::CondOp::StringEqual(String::from($val))
        };
        (~= str($val:literal)) => {
            {
                let regex = ::regex::Regex::new($val).unwrap();
                crate::filter::CondOp::StringMatch(regex)
            }
        };
        (= bytes($val:literal)) => {
            crate::filter::CondOp::BytesEqual($val.to_vec())
        };
        (~= bytes($val:literal)) => {
            {
                let regex = ::regex::bytes::Regex::new($val).unwrap();
                crate::filter::CondOp::BytesMatch(regex)
            }
        };
        (= u64($val:literal)) => {
            crate::filter::CondOp::U64Equal($val)
        };
        (< u64($val:literal)) => {
            crate::filter::CondOp::U64Less($val)
        };
        (= i64($val:literal)) => {
            crate::filter::CondOp::I64Equal($val)
        };
        (< i64($val:literal)) => {
            crate::filter::CondOp::I64Less($val)
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
            crate::filter::Cond {
                var: var!($($var)*),
                op: crate::filter::CondFullOp {
                    op: op!($($op)*),
                    negated: false,
                },
            }
        };
    }

    macro_rules! filter {
        ($(($($cond:tt)*))|*) => {
            crate::filter::Filter {
                conds: vec![$(cond!($($cond)*)),*]
            }
        };
        ($($cond:tt)*) => {
            filter!(($($cond)*))
        };
    }

    #[test]
    fn eval_bool_equal() {
        use protobuf::well_known_types::wrappers::BoolValue;
        let mut message = BoolValue::default();

        let filter = filter!(var(1) = true);

        message.value = true;
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = false;
        assert_eq!(filter.eval_message(&message).unwrap(), false);
    }

    #[test]
    fn eval_string_equal() {
        use protobuf::well_known_types::wrappers::StringValue;
        let mut message = StringValue::default();

        let filter = filter!(var(1) = str("foo"));

        message.value = String::from("foo");
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = String::from("bar");
        assert_eq!(filter.eval_message(&message).unwrap(), false);
    }

    #[test]
    fn eval_string_match() {
        use protobuf::well_known_types::wrappers::StringValue;
        let mut message = StringValue::default();

        let filter = filter!(var(1) ~= str("^ba(r|z)$"));

        message.value = String::from("foo");
        assert_eq!(filter.eval_message(&message).unwrap(), false);

        message.value = String::from("bar");
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = String::from("baz");
        assert_eq!(filter.eval_message(&message).unwrap(), true);
    }

    #[test]
    fn eval_bytes_equal() {
        use protobuf::well_known_types::wrappers::BytesValue;
        let mut message = BytesValue::default();

        let filter = filter!(var(1) = bytes(b"\x00\x11\x00"));

        message.value = b"\x00\x11\x00".to_vec();
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = b"\x11\x00\x11".to_vec();
        assert_eq!(filter.eval_message(&message).unwrap(), false);
    }

    #[test]
    fn eval_bytes_match() {
        use protobuf::well_known_types::wrappers::BytesValue;
        let mut message = BytesValue::default();

        let filter = filter!(var(1) ~= bytes("^(\x00|\x11)+$"));

        message.value = b"\x00\x00\x11\x00\x00".to_vec();
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = b"\x00\x11\x00\x11\x00".to_vec();
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = b"\x00\x22\x00".to_vec();
        assert_eq!(filter.eval_message(&message).unwrap(), false);
    }

    #[test]
    fn eval_u64_equal() {
        use protobuf::well_known_types::wrappers::UInt64Value;
        let mut message = UInt64Value::default();

        let filter = filter!(var(1) = u64(42));

        message.value = 42;
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = 1337;
        assert_eq!(filter.eval_message(&message).unwrap(), false);
    }

    #[test]
    fn eval_u64_less() {
        use protobuf::well_known_types::wrappers::UInt64Value;
        let mut message = UInt64Value::default();

        let filter = filter!(var(1) < u64(42));

        message.value = 7;
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = 42;
        assert_eq!(filter.eval_message(&message).unwrap(), false);

        message.value = 1337;
        assert_eq!(filter.eval_message(&message).unwrap(), false);
    }

    #[test]
    fn eval_i64_equal() {
        use protobuf::well_known_types::wrappers::Int64Value;
        let mut message = Int64Value::default();

        let filter = filter!(var(1) = i64(-42));

        message.value = -42;
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = 42;
        assert_eq!(filter.eval_message(&message).unwrap(), false);

        message.value = -1337;
        assert_eq!(filter.eval_message(&message).unwrap(), false);
    }

    #[test]
    fn eval_i64_less() {
        use protobuf::well_known_types::wrappers::Int64Value;
        let mut message = Int64Value::default();

        let filter = filter!(var(1) < i64(-42));

        message.value = -1337;
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = -42;
        assert_eq!(filter.eval_message(&message).unwrap(), false);

        message.value = 42;
        assert_eq!(filter.eval_message(&message).unwrap(), false);
    }

    #[test]
    fn eval_negation() {
        use protobuf::well_known_types::wrappers::BoolValue;
        let mut message = BoolValue::default();

        let filter = filter!(not var(1) = false);

        message.value = true;
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = false;
        assert_eq!(filter.eval_message(&message).unwrap(), false);
    }

    #[test]
    fn eval_u32_coercion() {
        use protobuf::well_known_types::wrappers::UInt32Value;
        let mut message = UInt32Value::default();

        message.value = 42;
        assert!(filter!(var(1) = u64(42)).eval_message(&message).unwrap());
        assert!(filter!(var(1) < u64(1337)).eval_message(&message).unwrap());
    }

    #[test]
    fn eval_i32_coercion() {
        use protobuf::well_known_types::wrappers::Int32Value;
        let mut message = Int32Value::default();

        message.value = -42;
        assert!(filter!(var(1) = i64(-42)).eval_message(&message).unwrap());
        
        message.value = -1337;
        assert!(filter!(var(1) < i64(-42)).eval_message(&message).unwrap());
    }

    #[test]
    fn eval_multi_cond() {
        use protobuf::well_known_types::wrappers::Int64Value;
        let mut message = Int64Value::default();

        let filter = filter! {
            (var(1) < i64(-42)) | (var(1) = i64(0)) | (not var(1) < i64(42))
        };

        message.value = -1337;
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = -42;
        assert_eq!(filter.eval_message(&message).unwrap(), false);

        message.value = 0;
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = 11;
        assert_eq!(filter.eval_message(&message).unwrap(), false);

        message.value = 42;
        assert_eq!(filter.eval_message(&message).unwrap(), true);

        message.value = 1337;
        assert_eq!(filter.eval_message(&message).unwrap(), true);
    }

    #[test]
    fn eval_nested_message() {
        let mut message = rrg_proto::startup::Startup::default();
        message.mut_metadata().mut_version().set_major(3);
        message.mut_metadata().mut_version().set_minor(2);
        message.mut_metadata().mut_version().set_patch(1);

        assert!(filter!(var(1:3:1) = u64(3)).eval_message(&message).unwrap());
        assert!(filter!(var(1:3:2) = u64(2)).eval_message(&message).unwrap());
        assert!(filter!(var(1:3:3) = u64(1)).eval_message(&message).unwrap());
    }

    #[test]
    fn eval_invalid_field_num() {
        let error = filter!(var(1:3:42) = u64(42))
            .eval_message(&rrg_proto::startup::Startup::default())
            .unwrap_err();

        match error.repr {
            ErrorRepr::InvalidFieldNum { message_name, field_num } => {
                assert_eq!(message_name, "rrg.startup.Version");
                assert_eq!(field_num, 42);
            }
            _ => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn eval_non_singular_field() {
        let error = filter!(var(2) = str("--foo"))
            .eval_message(&rrg_proto::startup::Startup::default())
            .unwrap_err();

        match error.repr {
            ErrorRepr::NonSingularField { field_name } => {
                assert_eq!(field_name, "rrg.startup.Startup.args");
            }
            _ => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn eval_non_message_field_access() {
        let error = filter!(var(1:2:3) = u64(42))
            .eval_message(&rrg_proto::startup::Version::default())
            .unwrap_err();

        match error.repr {
            ErrorRepr::NonMessageFieldAccess { field_name } => {
                assert_eq!(field_name, "rrg.startup.Version.major");
            }
            _ => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn eval_type_mismatch() {
        let error = filter!(var(1) = str("foo"))
            .eval_message(&rrg_proto::startup::Version::default())
            .unwrap_err();

        match error.repr {
            ErrorRepr::TypeMismatch { var_type, op_type } => {
                assert_eq!(var_type, protobuf::reflect::RuntimeType::U32);
                assert_eq!(op_type, protobuf::reflect::RuntimeType::String);
            }
            _ => panic!("unexpected error: {error}"),
        }
    }

    #[test]
    fn eval_set_empty() {
        use protobuf::well_known_types::wrappers::UInt64Value;
        let mut message = UInt64Value::default();
        message.value = 42;

        assert_eq!(FilterSet::empty().eval_message(&message).unwrap(), true);
    }

    #[test]
    fn eval_set_single() {
        use protobuf::well_known_types::wrappers::UInt64Value;
        let mut message = UInt64Value::default();

        let filters = std::iter::once(filter!(var(1) = u64(42)))
            .collect::<FilterSet>();

        message.value = 42;
        assert_eq!(filters.eval_message(&message).unwrap(), true);

        message.value = 1337;
        assert_eq!(filters.eval_message(&message).unwrap(), false);
    }

    #[test]
    fn eval_set_multiple() {
        use protobuf::well_known_types::wrappers::UInt64Value;
        let mut message = UInt64Value::default();

        let filters = [
            filter!(not var(1) < u64(42)),
            filter!(var(1) < u64(1337)),
        ].into_iter().collect::<FilterSet>();

        message.value = 17;
        assert_eq!(filters.eval_message(&message).unwrap(), false);

        message.value = 42;
        assert_eq!(filters.eval_message(&message).unwrap(), true);

        message.value = 1337;
        assert_eq!(filters.eval_message(&message).unwrap(), false);
    }

    #[test]
    fn filter_to_string_empty() {
        assert_eq! {
            filter!().to_string(),
            "⊥"
        };
    }

    #[test]
    fn filter_to_string_single() {
        assert_eq! {
            filter! {
                var(1) = str("foo")
            }.to_string(),
            "𝛸(1) = \"foo\""
        };
    }

    #[test]
    fn filter_to_string_multiple() {
        assert_eq! {
            filter! {
                (var(4:2) < u64(42)) | (var(1:3:3:7) = str("bar"))
            }.to_string(),
            "𝛸(4.2) < 42 ∨ 𝛸(1.3.3.7) = \"bar\""
        };
    }

    #[test]
    fn cond_to_string() {
        assert_eq! {
            cond!(not var(1:3:3:7) = str("foo")).to_string(),
            "𝛸(1.3.3.7) ≠ \"foo\""
        };
    }

    #[test]
    fn cond_var_to_string() {
        assert_eq!(var!(1).to_string(), "𝛸(1)");
        assert_eq!(var!(4:2).to_string(), "𝛸(4.2)");
        assert_eq!(var!(1:3:3:7).to_string(), "𝛸(1.3.3.7)");
    }

    #[test]
    fn cond_full_op_to_string() {
        assert_eq! {
            cond!(var(0) = true).to_string(),
            "𝛸(0) = true"
        };
        assert_eq! {
            cond!(not var(0) = false).to_string(),
            "𝛸(0) ≠ false",
        };
        assert_eq! {
            cond!(not var(0) = u64(42)).to_string(),
            "𝛸(0) ≠ 42"
        };
        assert_eq! {
            cond!(not var(0) < u64(1337)).to_string(),
            "𝛸(0) ≮ 1337"
        };
    }

    #[test]
    fn cond_op_to_string() {
        assert_eq!(op!(= true).to_string(), "= true");
        assert_eq!(op!(= false).to_string(), "= false");

        assert_eq!(op!(= str("foo")).to_string(), "= \"foo\"");
        assert_eq!(op!(~= str("foo+")).to_string(), "≃ \"foo+\"");

        assert_eq!(op!(= i64(-42)).to_string(), "= -42");
        assert_eq!(op!(< i64(1337)).to_string(), "< 1337");
    }
}
