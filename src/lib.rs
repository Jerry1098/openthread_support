#![no_std]

use anyhow::{Error, Ok, Result};
use core::{
    net::{Ipv4Addr, Ipv6Addr},
    usize,
};

/// Support class to manage ip translation in openthread projects
pub struct OtIpManager {
    network_prefix: Ipv6Addr,
    prefix_length: u8,
}

impl OtIpManager {
    /// Create a new instance for a provided tlv openthread dataset
    pub fn new(tlv_dataset: &str) -> Result<Self> {
        let network_prefix = get_network_prefix_from_tlv(tlv_dataset)?;
        let prefix_length = 96;
        Ok(OtIpManager{
            network_prefix,
            prefix_length
        })
    }

    pub fn to_ipv6(&self, ip: Ipv4Addr) -> Result<Ipv6Addr> {
        Ok(synthesize_nat64(self.network_prefix, self.prefix_length, ip)?)
    }
}



/// This function mimics the NAT64 synthesis function Address::SynthesizeFromIp4Address
/// from the OpenThread codebase.
pub fn synthesize_nat64(prefix: Ipv6Addr, prefix_len: u8, ipv4: Ipv4Addr) -> Result<Ipv6Addr> {
    // Validate the prefix length
    if ![32, 40, 48, 56, 64, 96].contains(&prefix_len) {
        return Err(Error::msg(
            "Invalid prefix length: must be 32, 40, 48, 56, 64, or 96 bits",
        ));
    }

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

    Ok(Ipv6Addr::from(ipv6_bytes))
}

/// This function calls [`decode_tlv`] with the default sizes for TLV decoding.
/// The default sizes are:
/// - `MAX_VALUE_LENGTH`: 32 bytes, which is the maximum length of a value in the TLV.
/// - `MAX_VALUES`: 41 values, which is the maximum number of TLVs defined in OpenThread's dataset.
pub fn default_decode_tlv(tlv: &str) -> Result<[(u8, u8, [u8; 32]); 41]> {
    decode_tlv::<32, 41>(tlv)
}

/// Decodes the provided TLV (Type-Length-Value) string into a tuple of (type, length, value).
/// The TLV string is expected to be in hexadecimal format, where each byte is represented by two hex characters.
/// The function returns an array of tuples, where each tuple contains the type byte, length byte, and value bytes.
pub fn decode_tlv<const MAX_VALUE_LENGTH: usize, const MAX_VALUES: usize>(
    tlv: &str,
) -> Result<[(u8, u8, [u8; MAX_VALUE_LENGTH]); MAX_VALUES]> {
    // TLV has the format: <type><length><value>
    // Example: 0e080000000000000001 -> type: 0e, length: 08, value: 000000000001
    // Read every two characters as a byte
    // After first type is read the next byte is the type definition of the next type

    // Array of [(type_byte, length_byte, value_bytes)]
    let mut decoded_tlv: [(u8, u8, [u8; MAX_VALUE_LENGTH]); MAX_VALUES] =
        [(0, 0, [0; MAX_VALUE_LENGTH]); MAX_VALUES];

    let mut type_byte = 0u8;
    let mut length_byte = 0u8;
    let mut value_bytes = [0u8; MAX_VALUE_LENGTH];
    let mut value_index: i16 = 0;
    let mut decoded_tlv_index = 0u8;

    for chunk in tlv.as_bytes().chunks(2) {
        if chunk.len() != 2 {
            return Err(Error::msg(
                "Invalid TLV format: each byte must be represented by two hex characters",
            ));
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
    Ok(decoded_tlv)
}

/// Extracts the given TLV type from the provided TLV string.
/// More efficient for single TLV extraction than `decode_tlv`.
/// Returns a string with the value of the provided TLV type
pub fn get_type_from_tlv(tlv: &str, tlv_type: TlvType) -> Result<&[u8]> {
    let mut i = 0;

    let tlv_bytes = tlv.as_bytes();
    let tlv_type_u8 = tlv_type as u8;

    loop {
        let type_pair = core::str::from_utf8(&tlv_bytes[i..=i + 1])?;
        let type_value = u8::from_str_radix(type_pair, 16)?;

        let type_length_pair = core::str::from_utf8(&tlv_bytes[i + 2..=i + 3])?;
        // double type length as legth is provided as pair of bytes but we are using single bytes in our index
        let type_length = u8::from_str_radix(type_length_pair, 16)? as usize * 2;

        // increase i by 4 (4 bytes used by type and length)
        i += 4;

        if type_value == tlv_type_u8 {
            let tlv_value = &tlv_bytes[i..i + type_length];
            // let tlv_value = core::str::from_utf8(&tlv_bytes[i..i + type_length])?;
            return Ok(tlv_value);
        }

        i += type_length;
        if i > tlv.len() {
            break;
        }
    }
    Err(Error::msg("Unable to find provided type in TLV"))
}

pub fn get_network_prefix_from_tlv(tlv: &str) -> Result<Ipv6Addr> {
    let tlv_type = TlvType::MeshLocalPrefix;
    let raw_prefix_value = get_type_from_tlv(tlv, tlv_type)?;

    let mut prefix_value: [u8; 16] = [0; 16];

    for (index, value) in raw_prefix_value.chunks(2).enumerate() {
        let pair = core::str::from_utf8(value)?;
        let value = u8::from_str_radix(pair, 16)?;
        prefix_value[index] = value;
    }

    Ok(Ipv6Addr::from(prefix_value))
}

/// Tlv Type enumeration for OpenThread MeshCoP (Mesh Commissioning Protocol) TLVs.
/// Same as OpenThread's Type in openthread/include/openthread/dataset.h
pub enum TlvType {
    /// meshcop Channel TLV
    Channel = 0,
    /// meshcop Pan Id TLV
    PanId = 1,
    /// meshcop Extended Pan Id TLV
    ExtPanId = 2,
    /// meshcop Network Name TLV
    NetworkName = 3,
    /// meshcop PSKc TLV
    Pskc = 4,
    /// meshcop Network Key TLV
    NetworkKey = 5,
    /// meshcop Network Key Sequence TLV
    NetworkKeySequence = 6,
    /// meshcop Mesh Local Prefix TLV
    MeshLocalPrefix = 7,
    /// meshcop Steering Data TLV
    SteeringData = 8,
    /// meshcop Border Agent Locator TLV
    BorderAgentRloc = 9,
    /// meshcop Commissioner ID TLV
    CommissionerId = 10,
    /// meshcop Commissioner Session ID TLV
    CommSessionId = 11,
    /// meshcop Security Policy TLV
    SecurityPolicy = 12,
    /// meshcop Get TLV
    Get = 13,
    /// meshcop Active Timestamp TLV
    ActiveTimestamp = 14,
    /// meshcop Commissioner UDP Port TLV
    CommissionerUdpPort = 15,
    /// meshcop State TLV
    State = 16,
    /// meshcop Joiner DTLS Encapsulation TLV
    JoinerDtls = 17,
    /// meshcop Joiner UDP Port TLV
    JoinerUdpPort = 18,
    /// meshcop Joiner IID TLV
    JoinerIid = 19,
    /// meshcop Joiner Router Locator TLV
    JoinerRloc = 20,
    /// meshcop Joiner Router KEK TLV
    JoinerRouterKek = 21,
    /// meshcop Provisioning URL TLV
    ProvisioningUrl = 32,
    /// meshcop Vendor Name TLV
    VendorName = 33,
    /// meshcop Vendor Model TLV
    VendorModel = 34,
    /// meshcop Vendor SW Version TLV
    VendorSwVersion = 35,
    /// meshcop Vendor Data TLV
    VendorData = 36,
    /// meshcop Vendor Stack Version TLV
    VendorStackVersion = 37,
    /// meshcop UDP encapsulation TLV
    UdpEncapsulation = 48,
    /// meshcop IPv6 address TLV
    Ipv6Address = 49,
    /// meshcop Pending Timestamp TLV
    PendingTimestamp = 51,
    /// meshcop Delay Timer TLV
    DelayTimer = 52,
    /// meshcop Channel Mask TLV
    ChannelMask = 53,
    /// meshcop Count TLV
    Count = 54,
    /// meshcop Period TLV
    Period = 55,
    /// meshcop Scan Duration TLV
    ScanDuration = 56,
    /// meshcop Energy List TLV
    EnergyList = 57,
    /// meshcop Thread Domain Name TLV
    ThreadDomainName = 59,
    /// meshcop Wake-up Channel TLV
    WakeupChannel = 74,
    /// meshcop Discovery Request TLV
    DiscoveryRequest = 128,
    /// meshcop Discovery Response TLV
    DiscoveryResponse = 129,
    /// meshcop Joiner Advertisement TLV
    JoinerAdvertisement = 241,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_synthesize_nat64() {
        let prefix = Ipv6Addr::new(0xfdb4, 0x4e7f, 0x4e8d, 0x2, 0, 0, 0, 0);
        let ipv4 = Ipv4Addr::new(192, 168, 1, 228);
        let expected = Ipv6Addr::new(0xfdb4, 0x4e7f, 0x4e8d, 0x2, 0x0, 0x0, 0xc0a8, 0x1e4);

        let result = synthesize_nat64(prefix, 96, ipv4).unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_decode_tlv() {
        let tlv = "0e080000000000000001";
        let mut value = [0u8; 32];
        value[7] = 1;
        let expected_entry = (0x0e, 0x08, value);
        let expected = [expected_entry; 32];
        let result = decode_tlv::<32, 32>(tlv).unwrap();
        assert_eq!(result[0], expected[0]);
    }

    #[test]
    fn test_decode_tlv_get_network_prefix() {
        let tlv = "0e080000000000010000000300000f4a0300001035060004001fffe002089ae0cd93577ab6620708fdaf7669ebb564510510aa5dfb14f0102499a78d22778d4a33ac030e68612d7468726561642d393138370102918704108a843e6e124cd4d5869e337510aaca2f0c0402a0f7f8";
        let decoded_tlv = default_decode_tlv(tlv).unwrap();
        let network_prefix = decoded_tlv
            .iter()
            .find(|&&(t, _, _)| t == TlvType::MeshLocalPrefix as u8);
        assert!(network_prefix.is_some(), "Network prefix TLV not found");
        let (_, length, value) = network_prefix.unwrap();
        assert_eq!(*length, 8, "Network prefix length is not 8 bytes");
        let prefix_bytes = &value[..8];
        let ipv6_prefix = Ipv6Addr::new(
            u16::from_be_bytes([prefix_bytes[0], prefix_bytes[1]]),
            u16::from_be_bytes([prefix_bytes[2], prefix_bytes[3]]),
            u16::from_be_bytes([prefix_bytes[4], prefix_bytes[5]]),
            u16::from_be_bytes([prefix_bytes[6], prefix_bytes[7]]),
            0,
            0,
            0,
            0,
        );
        assert_eq!(
            ipv6_prefix,
            Ipv6Addr::new(
                0xfdaf, 0x7669, 0xebb5, 0x6451, 0x0000, 0x0000, 0x0000, 0x0000
            ),
            "Network prefix does not match expected value"
        );
    }

    #[test]
    fn test_decode_single_tlv() {
        let tlv = "0e080000000000010000000300000f4a0300001035060004001fffe002089ae0cd93577ab6620708fdaf7669ebb564510510aa5dfb14f0102499a78d22778d4a33ac030e68612d7468726561642d393138370102918704108a843e6e124cd4d5869e337510aaca2f0c0402a0f7f8";
        let tlv_type = TlvType::MeshLocalPrefix;
        let raw_prefix_value = get_type_from_tlv(tlv, tlv_type).unwrap();

        let mut prefix_value: [u8; 16] = [0; 16];

        for (index, value) in raw_prefix_value.chunks(2).enumerate() {
            let pair = core::str::from_utf8(value).unwrap();
            let value = u8::from_str_radix(pair, 16).unwrap();
            prefix_value[index] = value;
        }

        let ip_prefix = Ipv6Addr::from(prefix_value);

        assert_eq!(
            ip_prefix,
            Ipv6Addr::new(
                0xfdaf, 0x7669, 0xebb5, 0x6451, 0x0000, 0x0000, 0x0000, 0x0000
            ),
            "Network prefix does not match expected value"
        )
    }


    #[test]
    fn test_get_network_prefix_from_tlv() {
        let tlv = "0e080000000000010000000300000f4a0300001035060004001fffe002089ae0cd93577ab6620708fdaf7669ebb564510510aa5dfb14f0102499a78d22778d4a33ac030e68612d7468726561642d393138370102918704108a843e6e124cd4d5869e337510aaca2f0c0402a0f7f8";
        let network_prefix = get_network_prefix_from_tlv(tlv).unwrap();

        assert_eq!(
            network_prefix,
            Ipv6Addr::new(
                0xfdaf, 0x7669, 0xebb5, 0x6451, 0x0000, 0x0000, 0x0000, 0x0000
            ),
            "Network prefix does not match expected value"
        )
    }
}
