#![cfg_attr(not(feature = "std"), no_std, no_main)]

use ink::prelude::vec::Vec;

/// content identifier
#[derive(Debug, PartialEq, Eq, Clone)]
#[ink::scale_derive(Encode, Decode, TypeInfo)]
pub struct Filename(pub Vec<u8>);

#[derive(Debug, PartialEq, Eq, Clone)]
#[ink::scale_derive(Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
pub struct CID(pub Vec<u8>);

#[derive(Debug, PartialEq, Eq, Clone)]
#[ink::scale_derive(Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
pub struct Intent(pub Vec<u8>);

#[derive(Debug, PartialEq, Eq, Clone)]
#[ink::scale_derive(Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
pub struct Entry {
    cid: CID,
    intent: Intent,
}

#[ink::contract]
mod pass_store {

    use super::*;
    use ink::storage::Mapping;

    #[ink(storage)]
    pub struct PasswordBasedDocStore {
        registry: Mapping<Filename, Entry>,
        meta: Vec<Filename>,
    }

    impl PasswordBasedDocStore {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                registry: Mapping::default(),
                meta: Vec::new(),
            }
        }

        #[ink(message)]
        pub fn read_all(&self) -> Vec<Filename> {
            // this should really be bounded and paginated, but w/e
            self.meta.clone()
        }

        /// register a cid <> intent mapping
        #[ink(message)]
        pub fn register(&mut self, filename: Filename, cid: CID, intent: Intent) {
            let entry = Entry { cid, intent };
            // TODO: duplicate filename check (later)
            self.meta.push(filename.clone());
            self.registry.insert(filename, &entry);
            // TODO: emit event
        }

        /// read cid and intent based on filename
        #[ink(message)]
        pub fn read(&self, filename: Filename) -> Option<Entry> {
            self.registry.get(filename)
        }

        #[ink(message)]
        pub fn remove(&mut self, filename: Filename) -> Option<Entry> {
            self.registry.take(filename)
        }
    }
}
