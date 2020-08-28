use crate::session::error::TimeMicrosConversionError;

/// Coverts time from protobuf micros (defined as microseconds from epoch
/// time: 1970-01-01T00:00:00.000000000Z) to std::time::SystemTime.
pub fn time_from_micros(micros: u64) -> Result<std::time::SystemTime, TimeMicrosConversionError> {
    let result = std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_micros(micros));

    if result.is_none(){
        return Err(TimeMicrosConversionError {micros});
    }

    Ok(result.unwrap())
}
