/// Coverts time from protobuf micros (defined as microseconds from epoch
/// time: 1970-01-01T00:00:00.000000000Z) to std::time::SystemTime.
pub fn time_from_micros(micros: u64) -> std::time::SystemTime {
    return std::time::UNIX_EPOCH
        .checked_add(std::time::Duration::from_micros(micros))
        .unwrap_or_else(|| {
            panic!(
                "Cannot create std::time::SystemTime from micros: {}",
                micros
            ) // It should never happen as std::time::SystemTime supports all u64 values.
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_from_micros_doesnt_panic_on_edge_values_test() {
        time_from_micros(u64::MIN);
        time_from_micros(u64::MAX / 2);
        time_from_micros(u64::MAX);
    }
}
