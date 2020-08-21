use crate::session::{ParseError, UnknownEnumValueError};

pub trait ProtoEnum<Proto> {
    // Returns a default value for given Protobuf definition.
    fn default() -> Proto;

    // Returns value of the enum or None if the input i32 does not describe any know enum value.
    // ::prost::Enumeration cannot be used instead, because it's not a trait.
    fn from_i32(val: i32) -> Option<Proto>;
}

// Maps the raw integer value to enum value or returns ParseError when the value cannot be mapped.
pub fn parse_enum<T: ProtoEnum<T>>(raw_enum_value: Option<i32>) -> Result<T, ParseError> {
    match raw_enum_value {
        Some(int_value) => match T::from_i32(int_value) {
            Some(parsed_value) => Ok(parsed_value),
            None => Err(ParseError::from(UnknownEnumValueError::new(
                std::any::type_name::<T>(),
                int_value,
            ))),
        },
        None => Ok(T::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, ::prost::Enumeration)]
    pub enum TestEnum {
        One = 1,
        Two = 2,
    }

    impl ProtoEnum<TestEnum> for TestEnum {
        fn default() -> TestEnum { TestEnum::Two }
        fn from_i32(val: i32) -> Option<TestEnum> {
            TestEnum::from_i32(val)
        }
    }

    #[test]
    fn parse_empty_enum_test() {
        let empty: Option<i32> = None;
        let parsed : TestEnum = parse_enum(empty).unwrap();
        assert_eq!(parsed, TestEnum::Two);
    }

    #[test]
    fn parse_correct_enum_value_test() {
        let parsed : TestEnum = parse_enum(Some(1)).unwrap();
        assert_eq!(parsed, TestEnum::One);
    }

    #[test]
    fn parse_incorrect_enum_value_test() {
        let parsed : Result<TestEnum, ParseError> = parse_enum(Some(3));
        assert!(parsed.is_err());
        match parsed.unwrap_err() {
            ParseError::UnknownEnumValue(error) => {
                assert_eq!(error.enum_name, std::any::type_name::<TestEnum>());
                assert_eq!(error.value, 3);
            }
            e @ _ => panic!("Unexpected error type: {:?}", e),
        }
    }
}
