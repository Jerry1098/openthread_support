#![no_std]

use core::{
    net::{Ipv4Addr, Ipv6Addr},
    usize,
};

/// This function mimics the NAT64 synthesis function Address::SynthesizeFromIp4Address
/// from the OpenThread codebase.
pub fn synthesize_nat64(prefix: Ipv6Addr, prefix_len: u8, ipv4: Ipv4Addr) -> Ipv6Addr {
    assert!(
        [32, 40, 48, 56, 64, 96].contains(&prefix_len),
        "Invalid prefix length"
    );

    let mut ipv6_bytes = prefix.octets();
    let ipv4_bytes = ipv4.octets();

    let skip_index = 8; // kSkipIndex
    let mut ip6_index = (prefix_len / 8) as usize; // aPrefix.GetLength() / kBitsPerByte;

    for &b in ipv4_bytes.iter() {
        if ip6_index == skip_index {
            ip6_index += 1;
        }
        if ip6_index >= 16 {
            break;
        }
        ipv6_bytes[ip6_index] = b;
        ip6_index += 1;
    }

    Ipv6Addr::from(ipv6_bytes)
}

/// Decodes the provided TLV (Type-Length-Value) string into a tuple of (type, length, value).
/// The TLV string is expected to be in hexadecimal format, where each byte is represented by two hex characters.
/// The function returns an array of tuples, where each tuple contains the type byte, length byte, and value bytes.
pub fn decode_tlv<const MAX_VALUE_LENGTH: usize, const MAX_VALUES: usize>(
    tlv: &str,
) -> [(u8, u8, [u8; MAX_VALUE_LENGTH]); MAX_VALUES] {
    // TLV has the format: <type><length><value>
    // Example: 0e080000000000000001 -> type: 0e, length: 08, value: 000000000001
    // Read every two characters as a byte
    // After first type is read the next byte is the type definition of the next type

    // Max operational dataset length is 254: openthread/include/openthread/dataset.h
    // OT_OPERATIONAL_DATASET_MAX_LENGTH 254

    // Array of [type_byte, length_byte, value_bytes]
    let mut decoded_tlv: [(u8, u8, [u8; MAX_VALUE_LENGTH]); MAX_VALUES] =
        [(0, 0, [0; MAX_VALUE_LENGTH]); MAX_VALUES];

    let mut type_byte = 0u8;
    let mut length_byte = 0u8;
    let mut value_bytes = [0u8; MAX_VALUE_LENGTH];
    let mut value_index: i16 = 0;
    let mut decoded_tlv_index = 0u8;

    for chunk in tlv.as_bytes().chunks(2) {
        if chunk.len() != 2 {
            // TODO: Handle error
            continue;
        }

        let pair = core::str::from_utf8(chunk).unwrap();
        let value = u8::from_str_radix(pair, 16).unwrap();

        if value_index == 0 {
            type_byte = value;
            value_index = -1;
        } else if value_index == -1 {
            length_byte = value;
            value_index = 1;
        } else if value_index < length_byte as i16 {
            value_bytes[(value_index - 1) as usize] = value;
            value_index += 1;
        } else {
            // value_index == length_byte
            // We have read the entire value
            value_bytes[(value_index - 1) as usize] = value;

            // Process the TLV
            decoded_tlv[decoded_tlv_index as usize] = (type_byte, length_byte, value_bytes);
            decoded_tlv_index += 1;
            type_byte = 0;
            length_byte = 0;
            value_bytes = [0u8; MAX_VALUE_LENGTH];
            value_index = 0;
        }
    }

    decoded_tlv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthesize_nat64() {
        let prefix = Ipv6Addr::new(0xfdb4, 0x4e7f, 0x4e8d, 0x2, 0, 0, 0, 0);
        let ipv4 = Ipv4Addr::new(192, 168, 1, 228);
        let expected = Ipv6Addr::new(0xfdb4, 0x4e7f, 0x4e8d, 0x2, 0x0, 0x0, 0xc0a8, 0x1e4);

        let result = synthesize_nat64(prefix, 96, ipv4);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_decode_tlv() {
        let tlv = "0e080000000000000001";
        let mut value = [0u8; 32];
        value[7] = 1;
        let expected_entry = (0x0e, 0x08, value);
        let expected = [expected_entry; 32];
        let result = decode_tlv::<32, 32>(tlv);
        assert_eq!(result[0], expected[0]);
    }
}
