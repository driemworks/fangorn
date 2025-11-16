#![cfg_attr(not(feature = "std"), no_std, no_main)]

use ink::prelude::vec::Vec;

#[derive(Debug, PartialEq, Eq, Clone)]
#[ink::scale_derive(Encode, Decode, TypeInfo)]
#[cfg_attr(feature = "std", derive(ink::storage::traits::StorageLayout))]
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
    pub cid: CID,
    pub intent: Vec<u8>,
}

#[ink::contract]
pub mod fangorn_registry {
    use super::*;
    use ink::prelude::vec;
    use ink::storage::Mapping;

    #[ink(storage)]
    pub struct Contract {
        /// Map filename to entry
        registry: Mapping<Filename, Entry>,
        /// List of all registered filenames
        filenames: Vec<Filename>,
    }

    #[derive(Debug, PartialEq, Eq)]
    #[ink::scale_derive(Encode, Decode, TypeInfo)]
    pub enum Error {
        FilenameAlreadyExists,
        FilenameNotFound,
        Unauthorized,
    }

    impl Contract {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self {
                registry: Mapping::default(),
                filenames: vec![],
            }
        }

        /// Register an intent
        ///
        /// * `filename`: the globally unique filename 
        /// * `cid`: the content identifier
        /// * `intent`: a generic blob of SCALE encoded data
        #[ink(message)]
        pub fn register(
            &mut self,
            filename: Filename,
            cid: CID,
            intent: Vec<u8>,
        ) -> Result<(), Error> {
            // check duplicate filenames
            if self.registry.contains(&filename) {
                return Err(Error::FilenameAlreadyExists);
            }

            let entry = Entry { cid, intent };

            self.registry.insert(&filename, &entry);
            self.filenames.push(filename);

            Ok(())
        }

        /// Read entry by filename
        #[ink(message)]
        pub fn read(&self, filename: Filename) -> Option<Entry> {
            self.registry.get(&filename)
        }

        /// List all registered filenames (todo: pagination)
        #[ink(message)]
        pub fn read_all(&self) -> Vec<Filename> {
            self.filenames.clone()
            // let start = start as usize;
            // let end = core::cmp::min(start + limit as usize, self.filenames.len());

            // if start >= self.filenames.len() {
            //     return vec![];
            // }

            // self.filenames[start..end].to_vec()
        }

        /// Remove an entry
        #[ink(message)]
        pub fn remove(&mut self, filename: Filename) -> Result<Entry, Error> {
            let entry = self
                .registry
                .take(&filename)
                .ok_or(Error::FilenameNotFound)?;

            if let Some(pos) = self.filenames.iter().position(|f| f == &filename) {
                self.filenames.swap_remove(pos);
            }

            Ok(entry)
        }
    }
}
