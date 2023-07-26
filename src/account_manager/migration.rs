// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use crate::{
    account::AccountHandle,
    event::{emit_migration_progress, MigrationProgressType},
};

use chrono::prelude::Utc;
use serde::{Deserialize, Serialize};

use iota_migration::transaction::Vertex;
pub(crate) use iota_migration::{
    client::{
        migration::{
            create_migration_bundle, encode_migration_address, mine, sign_migration_bundle, Address as BeeAddress,
        },
        response::InputData,
    },
    crypto::keys::ternary::seed::Seed as TernarySeed,
    ternary::{T1B1Buf, T3B1Buf, TritBuf, TryteBuf},
    transaction::bundled::{BundledTransaction, BundledTransactionField},
};
use iota_migration::{
    crypto::hashes::ternary::{curl_p::CurlP, Hash as TernaryHash},
    ternary::{raw, Btrit},
    transaction::bundled,
};

use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    fs::OpenOptions,
    hash::{Hash, Hasher},
    io::Write,
    ops::Range,
    path::Path,
    time::Duration,
};

/// Migration address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationAddress {
    /// address tryte encoded
    pub trytes: String,
    /// address bech32 encoded
    pub bech32: String,
}

/// Migration data.
#[derive(Debug, Clone)]
pub struct MigrationData {
    /// Total seed balance.
    pub balance: u64,
    /// The index of the last checked address.
    /// Useful if you want to call the finder again.
    pub last_checked_address_index: u64,
    /// Migration inputs.
    pub inputs: Vec<InputData>,
    /// If any of the inputs are spent
    pub spent_addresses: bool,
}

/// Migration bundle.
#[derive(Debug, Clone)]
pub struct MigrationBundle {
    /// The bundle crackability if it was mined.
    pub crackability: f64,
    /// Migration bundle.
    pub bundle: Vec<BundledTransaction>,
}

/// Finds account data for the migration from legacy network.
pub struct MigrationDataFinder<'a> {
    pub(crate) nodes: &'a [&'a str],
    pub(crate) permanode: Option<&'a str>,
    seed: TernarySeed,
    pub(crate) seed_hash: u64,
    pub(crate) security_level: u8,
    pub(crate) gap_limit: u64,
    pub(crate) initial_address_index: u64,
}

/// Migration metadata.
pub(crate) struct MigrationMetadata {
    pub(crate) balance: u64,
    pub(crate) last_checked_address_index: u64,
    pub(crate) inputs: HashMap<Range<u64>, Vec<InputData>>,
    pub(crate) spent_addresses: bool,
}

#[derive(Serialize)]
struct LogAddress {
    address: String,
    balance: u64,
}

impl<'a> MigrationDataFinder<'a> {
    /// Creates a new migration accoutn data finder.
    pub fn new(nodes: &'a [&'a str], seed: &'a str) -> crate::Result<Self> {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        let seed_hash = hasher.finish();
        let seed = TernarySeed::from_trits(
            TryteBuf::try_from_str(seed)
                .map_err(|_| crate::Error::InvalidSeed)?
                .as_trits()
                .encode::<T1B1Buf>(),
        )
        .map_err(|_| crate::Error::InvalidSeed)?;
        Ok(Self {
            nodes,
            permanode: None,
            seed,
            seed_hash,
            security_level: 2,
            gap_limit: 30,
            initial_address_index: 0,
        })
    }

    /// Sets the permanode to use.
    pub fn with_permanode(mut self, permanode: &'a str) -> Self {
        self.permanode.replace(permanode);
        self
    }

    /// Sets the security level.
    pub fn with_security_level(mut self, level: u8) -> Self {
        self.security_level = level;
        self
    }

    /// Sets the gap limit.
    pub fn with_gap_limit(mut self, gap_limit: u64) -> Self {
        self.gap_limit = gap_limit;
        self
    }

    /// Sets the initial address index.
    pub fn with_initial_address_index(mut self, initial_address_index: u64) -> Self {
        self.initial_address_index = initial_address_index;
        self
    }

    pub(crate) async fn finish(
        &self,
        previous_inputs: HashMap<Range<u64>, Vec<InputData>>,
    ) -> crate::Result<MigrationMetadata> {
        let mut inputs: HashMap<Range<u64>, Vec<InputData>> = HashMap::new();
        let mut address_index = self.initial_address_index;
        let mut legacy_client_builder = iota_migration::ClientBuilder::new().quorum(true);
        if let Some(permanode) = self.permanode {
            legacy_client_builder = legacy_client_builder.permanode(permanode)?;
        }
        for node in self.nodes {
            legacy_client_builder = legacy_client_builder.node(node)?;
        }
        let mut legacy_client = legacy_client_builder.build()?;
        let mut balance = 0;
        let mut spent_addresses = false;
        loop {
            emit_migration_progress(MigrationProgressType::FetchingMigrationData {
                initial_address_index: address_index,
                final_address_index: address_index + self.gap_limit,
            })
            .await;
            let migration_inputs = legacy_client
                .get_account_data_for_migration()
                .with_seed(&self.seed)
                .with_security(self.security_level)
                .with_start_index(address_index)
                .with_gap_limit(self.gap_limit)
                .finish()
                .await?;
            if migration_inputs.2 {
                spent_addresses = true;
            }
            let mut current_inputs = migration_inputs.1;
            // Filter duplicates because when it's called another time it could return duplicated entries
            let mut unique_inputs = HashMap::new();
            for input in current_inputs {
                let mut exists = false;
                // check inputs on previous executions
                for previous_inputs in previous_inputs.values() {
                    if previous_inputs.contains(&input) {
                        exists = true;
                        break;
                    }
                }
                // check inputs on previous iterations
                if !exists {
                    for previous_inputs in inputs.values() {
                        if previous_inputs.contains(&input) {
                            exists = true;
                            break;
                        }
                    }
                }
                if !exists {
                    unique_inputs.insert(input.index, input);
                }
            }
            current_inputs = unique_inputs
                .into_iter()
                .map(|(_, input)| input)
                .collect::<Vec<InputData>>();
            let current_balance: u64 = current_inputs.iter().map(|d| d.balance).sum();
            balance += current_balance;
            inputs.insert(address_index..address_index + self.gap_limit, current_inputs);

            address_index += self.gap_limit;
            // if balance didn't change, we stop searching for balance
            if current_balance == 0 {
                break;
            }
        }

        Ok(MigrationMetadata {
            balance,
            last_checked_address_index: address_index,
            inputs,
            spent_addresses,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_bundle<P: AsRef<Path>>(
    account_handle: AccountHandle,
    data: &super::CachedMigrationData,
    seed: TernarySeed,
    address_inputs: Vec<&InputData>,
    bundle_mine: bool,
    timeout: Duration,
    offset: i64,
    log_file_path: P,
) -> crate::Result<MigrationBundle> {
    let mut legacy_client_builder = iota_migration::ClientBuilder::new().quorum(true);
    if let Some(permanode) = &data.permanode {
        legacy_client_builder = legacy_client_builder.permanode(permanode)?;
    }
    for node in &data.nodes {
        legacy_client_builder = legacy_client_builder.node(node)?;
    }
    let legacy_client = legacy_client_builder.build()?;

    match address_inputs.len() {
        0 => return Err(crate::Error::EmptyInputList),
        1 => {}
        _ if address_inputs.iter().any(|input| input.spent) => return Err(crate::Error::SpentAddressOnBundle),
        _ => {}
    }

    let deposit_address = account_handle.latest_address().await;
    let deposit_address_bech32 = deposit_address.address().to_bech32();
    let deposit_address = match BeeAddress::try_from_bech32(&deposit_address.address().to_bech32()) {
        Ok(BeeAddress::Ed25519(a)) => a,
        _ => return Err(crate::Error::InvalidAddress),
    };
    let deposit_address_trytes = encode_migration_address(deposit_address)?;

    let mut prepared_bundle = create_migration_bundle(
        &legacy_client,
        deposit_address,
        address_inputs.clone().into_iter().cloned().collect(),
    )
    .await?;
    let mut crackability = None;
    let mut spent_bundle_hashes = Vec::new();
    if bundle_mine && address_inputs.iter().any(|i| i.spent) {
        for input in &address_inputs {
            if let Some(bundle_hashes) = input.spent_bundlehashes.clone() {
                spent_bundle_hashes.extend(bundle_hashes);
            }
        }
        if !spent_bundle_hashes.is_empty() {
            emit_migration_progress(MigrationProgressType::MiningBundle {
                address: address_inputs
                    .iter()
                    .find(|i| i.spent)
                    .unwrap() // safe to unwrap: we checked that there's an spent address
                    .address
                    .to_inner()
                    .encode::<T3B1Buf>()
                    .iter_trytes()
                    .map(char::from)
                    .collect::<String>(),
            })
            .await;
            let mining_result = mine(
                prepared_bundle,
                data.security_level,
                spent_bundle_hashes.clone(),
                timeout.as_secs(),
                offset,
            )
            .await?;
            crackability = Some(mining_result.0.crackability);
            prepared_bundle = mining_result.1;
        }
    }

    emit_migration_progress(MigrationProgressType::SigningBundle {
        addresses: address_inputs
            .iter()
            .map(|i| {
                i.address
                    .to_inner()
                    .encode::<T3B1Buf>()
                    .iter_trytes()
                    .map(char::from)
                    .collect::<String>()
            })
            .collect(),
    })
    .await;
    let bundle = sign_migration_bundle(
        seed,
        prepared_bundle,
        address_inputs.clone().into_iter().cloned().collect(),
    )?;

    let bundle_hash = bundle
        .first()
        .unwrap()
        .bundle()
        .to_inner()
        .encode::<T3B1Buf>()
        .iter_trytes()
        .map(char::from)
        .collect::<String>();

    let mut log = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(log_file_path)?;
    let mut trytes = Vec::new();
    for i in 0..bundle.len() {
        let mut trits = TritBuf::<T1B1Buf>::zeros(8019);
        bundle.get(i).unwrap().as_trits_allocated(&mut trits);
        trytes.push(
            trits
                .encode::<T3B1Buf>()
                .iter_trytes()
                .map(char::from)
                .collect::<String>(),
        );
    }
    log.write_all(format!("bundleHash: {}\n", bundle_hash).as_bytes())?;
    log.write_all(format!("trytes: {:?}\n", trytes).as_bytes())?;
    log.write_all(
        format!(
            "receiveAddressTrytes: {}\n",
            deposit_address_trytes
                .to_inner()
                .encode::<T3B1Buf>()
                .iter_trytes()
                .map(char::from)
                .collect::<String>()
        )
        .as_bytes(),
    )?;
    log.write_all(format!("receiveAddressBech32: {}\n", deposit_address_bech32).as_bytes())?;
    log.write_all(format!("balance: {}\n", address_inputs.iter().map(|a| a.balance).sum::<u64>()).as_bytes())?;
    log.write_all(format!("timestamp: {}\n", Utc::now()).as_bytes())?;
    log.write_all(
        format!(
            "spentAddresses: {:?}\n",
            address_inputs
                .iter()
                .filter(|i| i.spent)
                .map(|i| serde_json::to_string_pretty(&LogAddress {
                    address: i
                        .address
                        .to_inner()
                        .encode::<T3B1Buf>()
                        .iter_trytes()
                        .map(char::from)
                        .collect::<String>(),
                    balance: i.balance
                })
                .unwrap())
                .collect::<Vec<String>>()
        )
        .as_bytes(),
    )?;
    let spent_bundle_hashes = match spent_bundle_hashes.is_empty() {
        false => format!("{:?}", spent_bundle_hashes),
        true => "null".to_string(),
    };
    log.write_all(format!("spentBundleHashes: {}\n", spent_bundle_hashes).as_bytes())?;
    log.write_all(format!("mine: {}\n", bundle_mine).as_bytes())?;
    log.write_all(
        format!(
            "crackability: {}\n",
            if let Some(crackability) = crackability {
                crackability.to_string()
            } else {
                "null".to_string()
            }
        )
        .as_bytes(),
    )?;
    log.write_all(b"\n\n")?;

    Ok(MigrationBundle {
        crackability: crackability.unwrap_or_default(),
        bundle,
    })
}

pub(crate) async fn send_bundle(
    nodes: &[&str],
    bundle: Vec<BundledTransaction>,
) -> crate::Result<iota_migration::crypto::hashes::ternary::Hash> {
    let bytes = isc_req_from_bundle(bundle);
    // TODO ...
    // ---
    let trits = TritBuf::<T1B1Buf>::zeros(BundledTransaction::trit_len());
    let mut curl = CurlP::new();
    let tail_transaction_hash = TernaryHash::from_inner_unchecked(curl.digest(&trits));
    Ok(tail_transaction_hash)
}

pub fn isc_param_bytes_from_bundle(bundle: Vec<BundledTransaction>) -> Vec<u8> {
    let raw_trytes: Vec<String> = bundle.iter().map(tx_trytes).collect();
    let mut encoded_bundle = Vec::<u8>::new();
    encoded_bundle.push(raw_trytes.len() as u8);

    // t5b1 encoding doesn't seem to work properly.
    // for tx_trytes in raw_trytes {
    //     // use T5B1 encode to convert string trytes into bytes
    //     let buf = tx_trytes
    //         .chars()
    //         .map(iota_migration::ternary::Tryte::try_from)
    //         .collect::<Result<iota_migration::ternary::TryteBuf, _>>()
    //         .unwrap()
    //         .as_trits()
    //         .encode::<iota_migration::ternary::T5B1Buf>();

    //     // length prefix
    //     let buf_slice = buf.as_i8_slice();
    //     encoded_bundle.append(&mut (buf_slice.len() as u16).to_le_bytes().to_vec());
    //     // write the bytes
    //     for b in buf_slice {
    //         encoded_bundle.push(*b as u8)
    //     }
    //     // encoded_bundle.append(&mut tx_trytes.as_bytes().to_vec());
    // }

    //use UTF8 encoding for the trytes
    for tx_trytes in raw_trytes {
        encoded_bundle.append(&mut (tx_trytes.len() as u16).to_le_bytes().to_vec());
        encoded_bundle.append(&mut tx_trytes.as_bytes().to_vec());
    }
    encoded_bundle
}

pub fn isc_req_from_bundle(bundle: Vec<BundledTransaction>) -> Vec<u8> {
    let mut req: Vec<u8> = vec![1]; // 1 is "requestKindOffLedgerISC"

    // TODO add the correct chainID, this is just a dummy one for testing
    let chain_id = "d5d8794ccc01f7ca0c7ccb6bcc6db4c97c322646da356f5f94b8946c03b08048";
    req.append(&mut hex::decode(chain_id).unwrap()); // ISC chainID (32 bytes) (aliasID of the chain output)
    req.append(&mut hex::decode("69492005").unwrap()); //contractHname
    req.append(&mut hex::decode("060d3f50").unwrap()); //migration entrypoint Hname

    // params
    req.push(1); // params len
    req.push(1); //key len
    req.append(&mut "b".as_bytes().to_vec()); // key "b"
    let mut bundle_bytes = isc_param_bytes_from_bundle(bundle);
    println!("{}", bundle_bytes.len());
    req.append(&mut isc_vlu_encode(bundle_bytes.len() as u64)); //bundle length
    req.append(&mut bundle_bytes); //bundle bytes

    req.append(&mut 0_u64.to_le_bytes().to_vec()); // nonce
    req.push(0); // gasbudget
    req.push(0); // allowance

    // add 33 bytes (32 for empty pubkey and one extra 0 for the signature)
    for _ in 0..33 {
        req.push(0);
    }

    req
}

// ---------------

// copied from iota.rs 656279e628e5f9d9288477cd4d2dc4170ea4bf0e util crate, that's not publicly exported for some reason
fn tx_trytes(tx: &bundled::BundledTransaction) -> String {
    let bundle = tx
        .bundle()
        .encode::<T3B1Buf>()
        .iter_trytes()
        .map(char::from)
        .collect::<String>();

    fn num_to_tryte_string(num: i64, len: usize) -> String {
        let mut trytes: TritBuf<T1B1Buf> = num.into();
        let n = len - trytes.len();
        for _ in 0..n {
            trytes.push(Btrit::Zero);
        }
        trytes
            .encode::<T3B1Buf>()
            .iter_trytes()
            .map(char::from)
            .collect::<String>()
    }

    tx.payload()
        .to_inner()
        .encode::<T3B1Buf>()
        .iter_trytes()
        .map(char::from)
        .collect::<String>()
        + &tx
            .address()
            .to_inner()
            .encode::<T3B1Buf>()
            .iter_trytes()
            .map(char::from)
            .collect::<String>()
        + &num_to_tryte_string(*tx.value().to_inner(), 81)
        + &tx
            .obsolete_tag()
            .to_inner()
            .encode::<T3B1Buf>()
            .iter_trytes()
            .map(char::from)
            .collect::<String>()
        + &num_to_tryte_string(*tx.timestamp().to_inner() as i64, 27)
        + &num_to_tryte_string(*tx.index().to_inner() as i64, 27)
        + &num_to_tryte_string(*tx.last_index().to_inner() as i64, 27)
        + &bundle
        + &tx
            .trunk()
            .encode::<T3B1Buf>()
            .iter_trytes()
            .map(char::from)
            .collect::<String>()
        + &tx
            .branch()
            .encode::<T3B1Buf>()
            .iter_trytes()
            .map(char::from)
            .collect::<String>()
        + &tx
            .tag()
            .to_inner()
            .encode::<T3B1Buf>()
            .iter_trytes()
            .map(char::from)
            .collect::<String>()
        + &num_to_tryte_string(*tx.attachment_ts().to_inner() as i64, 27)
        + &num_to_tryte_string(*tx.attachment_lbts().to_inner() as i64, 27)
        + &num_to_tryte_string(*tx.attachment_ubts().to_inner() as i64, 27)
        + &tx
            .nonce()
            .to_inner()
            .encode::<T3B1Buf>()
            .iter_trytes()
            .map(char::from)
            .collect::<String>()
}

// vlu (variable length unsigned) encoder
// custom encoding used by WASP/ISC - taken from:   https://github.com/iotaledger/wasp/blob/2071625c1500c211e590cdb6f836625347a99408/packages/wasmvm/wasmlib/src/wasmtypes/codec.rs#L192
pub fn isc_vlu_encode(mut value: u64) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    // first group of 7 bits
    // 1st byte encodes 0 as positive in bit 6
    let mut b = value as u8;
    value >>= 7;

    // keep shifting until all bits are done
    while value != 0 {
        // emit with continuation bit
        buf.push(b | 0x80);

        // next group of 7 bits
        b = value as u8;
        value >>= 7;
    }

    // emit without continuation bit
    buf.push(b);
    buf
}

/// --- tests

#[cfg(test)]
mod tests {
    use iota_migration::{ternary::TryteBuf, transaction::bundled::BundledTransaction};

    use crate::account_manager;

    fn valid_bundle() -> Vec<BundledTransaction> {
        let raw_trytes = vec![
            "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999TRANSFERNEGYZXAZKAPBOWHAVXHDWAJDYWOZWAMZODFBUBGCQEQ9XWCDUDBDFZXDTBGADXTWMDSDOEZD9NBQWWHA99999999999999999999WF99999999999999999999999999ZOQMFD99999999999C99999999APKIUYNXZLRLYCUYJRGTFTSYLCYJYEDCYJAFZOIRTYLLJNUOOJSGKPXLGKWADLHZICOUJXXLHEJSHYJHCMMKBXTDRTVMXNEIAYJCUMNCGKNQVSEUPKCZGJACCJ9AFFGVCGQXGSCKKOUBQQBJDXLMOMMVEZKRYZ99999V9PJWPAOYWURYYKGZZDBELYBWTXCFIVLJMUDSWWKFQQYTXFPNVJSCKBMDZRRRGBSYTQSWQDAGNZZ9999WF9999999999999999999999999QDJYGNAVF999999999MMMMMMMMMWVCLW9HGRAWJTEHKEBLBXTZCUXR",
            "QNABYZVQFZZWAAQKJIPNRWIRZJBOWMSLO9ROXXBEDNBBQRABWOBYI9BFXOU9YUS9CPAWRVKATGVUWUXTAMTRUMNR9BBCMYCPISYHWDOWCPROBZMYGUET9RRYVIOLXILTZNYMNAWXHDDIAGKMKLUDRSTGCTUBVDVPVDWYDKRWJPGTTZDAPVESCYBGGFORFDYYCUKWFKXQAWYZNWFYDIV9QMHGVNPVFRXBZFAFBVXWNEAYLEBNFN9PXRJQXAOGINGMFCKMPLMRDOWUZLLGEDVWVEIFFLNVITHGJXWKZE9QMPCRNUSZZBMQO9HK9DORTCNEIIECMTRQMAZKJFTFAJMXWBAGJ9LVWN9EYBZZTZZVPTLDRAIRZERLMKCVCSOMXTPFQOYJKCPQLPOUTYMEQENUCKJAZHJIJXGGBVEJQRZRRQWPSQ9JZPAEMESOZXKSNQJBLEDBCBZLTQVRDOJFGYHNGIYRVPATVRH9FLOGXWJTLWNDYABIDGFPFYYJFOKUKNOYCBOBTNHCCNHFCCKRFWPTFIEOESTTS9LXF9ABMLDJOZODMTLZZHKHTMCTVBGLOSHNUQ9TZKIEAX9AUMPHPSLDH99PCVWJSEGVKGSYMQWEKJCJBLGCRREHVTJETZEEODPZUMPALJEDRFNLITDLIXBDWDOL9OUXRLRZJYRHZIGGUGJZNWRIOFHTWXTMOMYQJBNKMNCTDPDKHYJNGBECRTPZAT999AYBMRM9VEOEIVZKRLHDVLREIIXXJYNMQYWTO9RSXSXOMCU9HYHZTZHGQOIFTNRQLLUPKWKGRUTOAPJSQAOVRAHGZJKHEAINBKSDDYARNALDVMILHYVPTOHCFVKECUIBMW99ILZGBOVURYKYVJBLGMRWIKSUTNBA9X9WMRZUZHDCWQKLTJBSBVLOZQFJDCYGZHNNITJLTDNSAVLAOO9KYBVQV9AQNJUQKPGCWBPVPVUETECYHMTDQRNUERA9WUXUXUUCAFQEANCOJCJWDHEDZPMMTTJXHPPNHMMJGXCACBZKSQXPLWYIDNHG9DEMFOC9WWYB9TCXMGLG9IAGYMLZDXIEMGACFVLGAXPBWULUHCHDZBDLVUBLTVGDEC9XOEGZTAYVAIJQ9EEYDBI9YSDZ9XNXOUDAU9XXLUUFXSXLHOTSCFMHEFABMK9XBZDCRSJMYEVIPSBKEALFXBQPFD9GGQJIOEKCQHFDZAOWJYWEWEFANXKFIQTNYBZBCQSKL9UMBDJQRHGAIMNLPLWHBPQOCMDLGRXELHW9ERUDI9SNQ9GWGTIFIOXZALQXRNVBVXDSJORLXMRRIAVWNMIAALDYRCVGPYZNYPQZOMIBM9FXCUUULTYIB9JOZR9UMEIGNER9XWO9IQLADAYHPJCDQTCWPCJNZHKPBOWNDPFFMDNIVWFBUUJMRQPZWFOXXF9EEMHEYUHNCBAJHWDIGWVXRTB9GOYUJWDRS9MILSQDQVZUKYVNUZUHZOJEGRZUGNZFPVZKDFCKAW9KNWNSHEWBQXITKKJWQAQYBUQEZKSFSOQBCVDSOGVAIHXLKUNGOMJVVRXXPCBLOILTIEQDWAGTPQWVNQNQMSNGFAQZVXHZIJFEGIFK9YOTSSGPZDAUUNQYKLFMMXPJZKUKTRBZZZP9JWTDRZTKNSJWEWOTORWTYSGOUNRLRIBPQIKZBSMILWPYEWNCGGOA9DAEDUEMYUHAFWB9XCZGILTQAPSNIFAWZSFHQFEPFGGRHUIZHZEXFHTUTY9UKGYDY9QHISNYBZFYSRHCCXVUMFLVMAJWYXUDGOSKXHCP9KKBMFJOCV9CTUQMBCW9FL9AXMABWPFYQDRYCAIPXLNJCWNKXDB9ZVKYRGVXQKGIRBAJB9XTDEKKEDGYCKLJOSJIIVSVOLDHISUSOJ9VIJLNWIOZCDBPNSJTFPJHCNLCGPWHJFQXEIRPUHLPF9JZKHMMPYJMWPVTSSGBABDXUPGDVDHVFPGOBTDTURWQTWTEKBFJLCXGESOWXRQPCTQYQBB9RQJUVYRXVMGNXOUIGMFDWBDEWKRMPOWZYGGYMLODKKXHLEUVBXKERAAHQYEYDIKYVABMO9KUJIARSEEUXTI9LBQLDCUFNDPZNWUSRWEE9KTQOXSNMCDQNGRBOZC9VVWWEEQAVFJYJPCPCYROCVE9WGHW9OSPFUKWDJXPXNMEHCKPOYBFWIURWEIEMAGWWPXVWDTMVUZVNYNYFOB9S9WIGHRNYVZBJEBBWQZIBWYIOZLKPGVNNCOLDIIUNNEQZYBDMYJDDSZ999999999999999999999999999999999999999999999999ZOQMFD99A99999999C99999999APKIUYNXZLRLYCUYJRGTFTSYLCYJYEDCYJAFZOIRTYLLJNUOOJSGKPXLGKWADLHZICOUJXXLHEJSHYJHCDJQNKMKBCABQASYTQCCBXLOMXXBHKQEQFLSYA9LBALUKPZPDZCXGMTAJZCHQVPNCQVJPMCRI9STF999999V9PJWPAOYWURYYKGZZDBELYBWTXCFIVLJMUDSWWKFQQYTXFPNVJSCKBMDZRRRGBSYTQSWQDAGNZZ9999999999999999999999999999999CVCXGNAVF999999999MMMMMMMMMPXUWJKPOHBMBDNZYWXEGGSEHGAK",
            "AAPQEIUASRNMDUIUIADDXTMZ9PZJDCCHMTSFQIRYNGCUABRFDIILYQNBLTJNZHALKF9OFJGYTTDVKIQADREXTTPLAVDYSACOMNHTLXMUQPLTWMKOJAL9PZKVVGSDULFVNJMRBHGGEGWDAPBJCLSCFJCMFGTXDBFMPBDFLULKVCPIYLBEYWHIKPOFNQUMCLIELTVRVISYIM9LJPTQXGZQTEKQPLWXKYMIOHISGGTKQUKICOKTEKDRFVNIMNVRSUQHIAOAVXLJKTDQTHLMCZLOZCZRJOTSAVRPRIJCV9ETFI9DSLDR9BVJDEXFVOJUCQLI9JZDO9FP9TRN9MTGET9RIPNTASM9AINXMLITAZOIAMFDZFVWBCUXWBZLNGTLM9CHHKVIZLUPWGUKFGNTBJHBCPDXFRKJHRGBGHMAOPRAAJUALPFKFEIUPKAHFB9PVTKITR9J9RES9HDQLNVQBYMZZBBSRKEUSKDNHXVWKYWPRGTYFSWVALINKDSSQCSU9NVSRF9YTODXOOGNBZYUEVCYMKBWVAULDICZKUNTQSWHGQ9FMAZMIQZPGLDDHTOMDNSGRHZIS9VRU9JPVL9HZO9XRNXH9KQIFAJOQYCRNNYBRUUIVOXMPZXRECBWFIZKIJVOKJYWCXQXTYNRLV9HSYQMKGEYLTUAHPMPWJBTGMHRUIRRMNQWMQYBOAKGJBNFJMDLSUYGFADJTLLUMHJDFKLJGRBTXFAXLMXWICKUWCKCNCXEUWQTUX9KBBINVFYKXBTSHGPLTCBTRGPZGJGCFYJICNPPZLXRWKHRGVHUOWDIODHEVLOJGBKMOCTPUTKGMNSTCTRW9RDQ9RUPSPYQSIZR9GHQUMRNVI9JOLSJHXXUMHKXV9JBE9OQOEXAKZWYIHRMAV9ZPIHFTHNZCTQKVDSRBXEMAJPTASTTLBBQGIKPQUOYXWKWGHGUNKEEZCCBYXECQKCUWGXTROWWWQPOUT99HBOCQWQEMINGIW9KRQDDYXFMSPJOACFUJAFRQWHCNUG9OBWWPKLBFJ9IRAMSAEWEAU9FCJJWX9NSMHUZQNRPDDSXGSTVCGNDWKJARLDJ9NYDCAXLCXHIWWAYEEUIOLQHGIUIWPYBP9QHEDERBACOZTIOKWZMZDNKXQVPBTJJB9PESPPBHVVGIWBLJPMNZL9ZLSXRWCYZDYUQQB9BTGUHYMGJSVJSLXDOJ9IPIPSTJRXDK9XFADXJCIXCXFHGRLUCRSBTWTTOWJDKBOXNYREKLIJULBTCKIFJG9QKUCWYRGC9KNOSYY9D9XLRVOLZ9VOWKVUJVUMNOQJUBCOAQZTACUAASLXUBVCXFWZFXJZLYDCNQVARIWYZRRVS9RWKJHYSRKWXIUNLPWJWYYQEMQAAUKTRXUSKXCPZNMNLI9BEQJAPAWDNCMOAVNIGQMTMCGHBHXJZLBMTVFARBUNFPDJPFYBGFRGJDYLQNMTYHIUZAVEYBSHLOXZ9MDHADDM9F9CKTJPGBZMMNEV9YKGLNYJQRS9PUSXIVWJIUADNFZBBBML9ONXFSAC9MJSGYAQKICRWP9LBGPQKZPPLACTYUMVAFSKWCEB9YAZUKAW9RWZOGAVFRXYZHUE9FPZXDRXCHPGWWUYLQTORQ9AEQMPHLEDQPJVLKWNUSMGZAOR9OIMGAUMFMNGXIZTDEP9FFLFSLJCNUAXHETXT9CLIJG9CWNJVGWZ9UYATOFASOIOCLAYVMSDJINXIHLFCMOQWJFILYWCKSGEOJKIBK9KDFEGRMTPEOBODFVMGSLAZXCBQLNPZIEKTADJYOZGXHBQWDQQYOFMJAKHUFTHWQNKSJKOCRRVMMWEVKSWTDRNCLJAMPIOOUZFKNRMJLIBKSEEQJQQ9RMDMHM9HWWHFOBDFNDANP9GYLORLPAHDQNIMKDMUARFCQEFNBJ9HHPLVBZNWBWETUYLRQHO9QUQXZTJHDVNRSMHWXOJNEJABLEOZCDCSFWLIWM9YBLDXCRNQUGOIDQQJLQSQDXVAIYBCVLXHUJDMZHMEBDIOLWFIEREKFMTLMENROGNMGZUQTQYLVLFSSLEO9JJT9MGUKKVCUZLCVEBMKIPYWAOJRHDJPMXORQXUD9HWNTOISQRQOMVKBDLDKDQICHFUTHIR9QTUOGLBXLROITQWMBEVUOADSANQTDXIRLQ9ARVAYEEGCYYKAUDFWIURWEIEMAGWWPXVWDTMVUZVNYNYFOB9S9WIGHRNYVZBJEBBWQZIBWYIOZLKPGVNNCOLDIIUNNEQZYBD9999999999999999999999999999999999999999999999999999999ZOQMFD99B99999999C99999999APKIUYNXZLRLYCUYJRGTFTSYLCYJYEDCYJAFZOIRTYLLJNUOOJSGKPXLGKWADLHZICOUJXXLHEJSHYJHCLSEIINLCTNVHBJEQEZCFTJBJMTI9OJTJIIFXMUDNXZBOQAJIMQQDWTTWKFJKLDLUFBCVXOGRJIAWA99999V9PJWPAOYWURYYKGZZDBELYBWTXCFIVLJMUDSWWKFQQYTXFPNVJSCKBMDZRRRGBSYTQSWQDAGNZZ9999999999999999999999999999999NGSXGNAVF999999999MMMMMMMMMZVOOETQIXXKTH9VISSPGETBLUTY",
            "WIJFPCX9BPLELNLCJRPSMXNPLQRYEJFTNBWLNQAJUMICHQAHZYMKWDMSCPZXEZVKMQGZPWQJDQSFNKESXQZHW9HWZUVZAWNHFZTMIDLAWNNPHYOJQUBZNYGFYFRTBMKPXKGNRJGUDULEO9EHSQMPARGCSXVLIRJEWWH9BELGRUQVMHMKSRECL9PXAFJ9JQOGWHNILROQLO9UVYUEFWJLMLMHIUUBZPDAPFDV9JPEPTEWVIAUZOYN9VDDIU9OMVZAWNOGCUJTXXGTPYXRQBDRIMF9NVFBWMKXNGLCXHQEOTJVJQNROTRGTKEHTUKCZBVSHREYWLHPSYUKJXOXMXEBNDIGLJAPKEXVMNFG9SXPUXOPDIGDSQJOALVTK9SLDDKPNAJBQCLEHRMKIDJJXQYZDDJLRUPJWPVZUQNIMDDMLBK9XYXHQZPJRFYIWTPDRYOEBTKIENEIIUGGYVKPUSABQDFJYNSOLHVCPJCITWCUYQBA9B9LNPLKQLPX9A9GAJWQSMJOJPWABUUQF9FVIOAAFIQIBXFIFBFPUACES9YHLAWPUCGMCYPSLK9ITKGDMHRJTIDVMPRQVMPNAJBV9VHJANGMIZDUJQSHAMBNWHJOG9ZURWJSTCKCQVHIYJFGDX9KIWUDGTFAZYGVALVLG9SDWNFMQ9YGKLPWNHZNWUKXUEFTEBZ9DZ9PPAKCDNSBMAICYGSHJZSOGKCWTQTOPTPYPDHQBWAJUDZJXKUO9MQPHAUKIIGYVDRSPVXYABDZJEIUVZKDR9SEACCPYFSFPVVMSVZZWMBUNAPEAIPNHANERACY9ERGHQXBSFIGYORXCIBLBTYVMSZ9IHQGRDSHXKRTZWASOXFGIGGLDKYAVWKGLIIDFDLMPZZDWWHWRSDGRHRSWOBYNRMSYGAGENVITEP9XTCVUXNDO9AQZGWLFVJQXIKGWZG9BYWKPQVHSMZFIGKSHGITHXSVJEDWEYTDIOGHEIINMPLWNZYHIKQVBRQGYFIMIF9DPVJLVJLVKGZGMT9P9U9OJDONSPMZXNMQLBCQB9VEKEKLZGWPGLPUH9KIHBEEAFRHBXZJJQLNSNMWVLWQQTYEROVTYIAEBYTQYBLFPCPFEVBIKHXRMOWJSHVUIQPAODHKMQYHBPPYFDVLODULIHSAIVHRAJQNMVYRVGXAWCY9IDAKWE9HYGKUQPBCCAAHBBGMUVZWNFIHAVIWWJYZLXPYNYUPNRRTHVMVBJCRSIRAOKGJSLOWLYGG9DAJPWQSYDUTWKKJFYVTQKN9ZNJFBHLWWK9FAOXCJZCZQDUYSHDWKWEYJYYRT9TDPOECSGWVCEXQXXIAZTBUXZWEKSGZ9ZFVKUVXPUIBVYVFCTIEBTTAQNTJZKNJ9WKVWYBHSGJNSLEFKMMJJQ9MGDUWLYEALLYGOEMQXHZITVJRILIZ99FVFYKXPEFCUWLIAAERTVNESWUYEBHELWVYPOAKFIQRPHYJOPYKTCPOYQXKXBJFDTKLGWTKXRSZQNVJURPCWQFYRUXBYYBAMRMBRKNQGZDEE9XQKNXOZXOCCNGMRMKTKQAGU9FWNRFVPETBZCQUUANZOQH9VUYY9GYDLKEJHGULOEDFUQPOOUWMYYRRNWDCTPQZYJIZFOZQMOGGHRZJOVJNLP9TZZ99SQYMKMJSGG9NPTIHLJUQIBEIWKOKENHQPNRWWECNQ9LLKVKGALVUGZCCTKJDPMAOZMUTPWUSVEHOPRPKQXE9FOT9MGYNQGKSYKSYLTBGLDN9QXEJMNXF9RCQRPPKQPWFVDRSANEEOFYLWGIBAW9SFTIVNJJRCQSPQSSPAYUAMGKIFLHSYJKNLLYUAFVVMHOSWFELDASAAPQNDYR9XGXSZQNCY9XCYLCMKHUKQGHTMQCFAYHGREJJCWHQZVOLUDMUPFFUJTIBJPUBOPBASHIFWOTNDTLTWPEIIFSWBMMKYR9WZSXZTRJZRLCSVGPJZHWAAKQJHEFZKB9MTFFAOXOUUADGOVWMB9MIQBEDFMFEXDZYWPDUVEBJBHUBVNYYXODBKDZHFIBVVUENTJQZXJVAIFCASYAWFFCRLCZLOPZNADEKGWDWFBAYYXQLOWHKHRQNFWMBLZCFAJNZXXNSAFKZUYEYFJVLHTZFFTWYWAJVBTTJ9MHVNDWCIENVGRM9AZ9VZNAOFPMWTWHAABRZTWFPEPXFWIURWEIEMAGWWPXVWDTMVUZVNYNYFOB9S9WIGHRNYVZBJEBBWQZIBWYIOZLKPGVNNCOLDIIUNNEQZYBD9999999999999999999999999999999999999999999999999999999ZOQMFD99C99999999C99999999APKIUYNXZLRLYCUYJRGTFTSYLCYJYEDCYJAFZOIRTYLLJNUOOJSGKPXLGKWADLHZICOUJXXLHEJSHYJHC9V9PJWPAOYWURYYKGZZDBELYBWTXCFIVLJMUDSWWKFQQYTXFPNVJSCKBMDZRRRGBSYTQSWQDAGNZZ9999VKBQRURURHEB9PXVIAGFNVB9LDZHCVHUZEUDQVMWSZIBQCSGBSVUFDUZBTJKCLUJIDNHDLYXFMWEA9999999999999999999999999999999CAMWGNAVF999999999MMMMMMMMMBNME9RGC9TEKIZHRGZYEJFLWHYS",
        ];
        // taken from https://explorer.iota.org/legacy-mainnet/transaction/UAXHEGENCKOFNNWMWKDQDYJMFJVEL9PUYJVFSZODOUVTKXKBKWHMRNSUOQ9QBMONSSJHNUORHYHZ99999

        raw_trytes
            .into_iter()
            .map(|tx| {
                BundledTransaction::from_trits(TryteBuf::try_from_str(tx).unwrap().as_trits())
                    .expect("Can't build transaction from String")
            })
            .collect()
    }

    // #[tokio::test]
    #[test]
    fn test_bundle_bin() {
        let bundle = valid_bundle();
        let bytes: Vec<u8> = account_manager::migration::isc_param_bytes_from_bundle(bundle);
        let s: String = bytes.into_iter().map(|b| format!("{b:02X?}")).collect();
        println!("{s}");
    }

    #[test]
    fn test_isc_req_bin() {
        let bundle = valid_bundle();
        let bytes = account_manager::migration::isc_req_from_bundle(bundle);
        let s: String = bytes.into_iter().map(|b| format!("{b:02X?}")).collect();
        println!("{s}");
    }
}
