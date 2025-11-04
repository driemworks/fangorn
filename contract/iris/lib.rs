#![cfg_attr(not(feature = "std"), no_std, no_main)]

use codec::{Encode, Decode};
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
        owner: AccountId,
        registry: Mapping<Filename, Entry>
    }

    impl PasswordBasedDocStore {
        
        #[ink(constructor)]
        pub fn new(owner: AccountId) -> Self {
            Self {
                owner,
                registry: Mapping::default(),
            }
        }

        /// register a cid <> intent mapping
        #[ink(message)]
        pub fn register(&mut self, filename: Filename, cid: CID, intent: Intent) {
            // TODO: Check owner
            let entry = Entry { cid, intent };
            self.registry.insert(filename, &entry);
            // TODO: emit event
        }

        /// read cid and intent based on filename
        #[ink(message)]
        pub fn read(&self, filename: Filename) -> Option<Entry> {
            self.registry.get(filename)
        }
    }

    // /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    // /// module and test functions are marked with a `#[test]` attribute.
    // /// The below code is technically just normal Rust code.
    // #[cfg(test)]
    // mod tests {
    //     /// Imports all the definitions from the outer scope so we can use them here.
    //     use super::*;

    //     /// We test if the default constructor does its job.
    //     #[ink::test]
    //     fn default_works() {
    //         let iris = Iris::default();
    //         assert_eq!(iris.get(), false);
    //     }

    //     /// We test a simple use case of our contract.
    //     #[ink::test]
    //     fn it_works() {
    //         let mut iris = Iris::new(false);
    //         assert_eq!(iris.get(), false);
    //         iris.flip();
    //         assert_eq!(iris.get(), true);
    //     }
    // }

    // /// This is how you'd write end-to-end (E2E) or integration tests for ink! contracts.
    // ///
    // /// When running these you need to make sure that you:
    // /// - Compile the tests with the `e2e-tests` feature flag enabled (`--features e2e-tests`)
    // /// - Are running a Substrate node which contains `pallet-contracts` in the background
    // #[cfg(all(test, feature = "e2e-tests"))]
    // mod e2e_tests {
    //     /// Imports all the definitions from the outer scope so we can use them here.
    //     use super::*;

    //     /// A helper function used for calling contract messages.
    //     use ink_e2e::ContractsBackend;

    //     /// The End-to-End test `Result` type.
    //     type E2EResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    //     /// We test that we can upload and instantiate the contract using its default constructor.
    //     #[ink_e2e::test]
    //     async fn default_works(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
    //         // Given
    //         let mut constructor = IrisRef::default();

    //         // When
    //         let contract = client
    //             .instantiate("iris", &ink_e2e::alice(), &mut constructor)
    //             .submit()
    //             .await
    //             .expect("instantiate failed");
    //         let call_builder = contract.call_builder::<Iris>();

    //         // Then
    //         let get = call_builder.get();
    //         let get_result = client.call(&ink_e2e::alice(), &get).dry_run().await?;
    //         assert!(matches!(get_result.return_value(), false));

    //         Ok(())
    //     }

    //     /// We test that we can read and write a value from the on-chain contract.
    //     #[ink_e2e::test]
    //     async fn it_works(mut client: ink_e2e::Client<C, E>) -> E2EResult<()> {
    //         // Given
    //         let mut constructor = IrisRef::new(false);
    //         let contract = client
    //             .instantiate("iris", &ink_e2e::bob(), &mut constructor)
    //             .submit()
    //             .await
    //             .expect("instantiate failed");
    //         let mut call_builder = contract.call_builder::<Iris>();

    //         let get = call_builder.get();
    //         let get_result = client.call(&ink_e2e::bob(), &get).dry_run().await?;
    //         assert!(matches!(get_result.return_value(), false));

    //         // When
    //         let flip = call_builder.flip();
    //         let _flip_result = client
    //             .call(&ink_e2e::bob(), &flip)
    //             .submit()
    //             .await
    //             .expect("flip failed");

    //         // Then
    //         let get = call_builder.get();
    //         let get_result = client.call(&ink_e2e::bob(), &get).dry_run().await?;
    //         assert!(matches!(get_result.return_value(), true));

    //         Ok(())
    //     }
    // }
}
