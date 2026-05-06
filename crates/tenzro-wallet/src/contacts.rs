//! Address book and contact management for Tenzro Network wallets.
//!
//! Provides a persistent contact registry mapping human-readable labels
//! to addresses, with optional TDIP identity linking.

use crate::error::{Result, WalletError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tenzro_types::primitives::Address;

/// A contact entry in the address book.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    /// Human-readable name/label
    pub name: String,
    /// On-chain address
    pub address: Address,
    /// Optional TDIP DID (e.g., did:tenzro:human:uuid)
    pub did: Option<String>,
    /// Optional notes
    pub notes: Option<String>,
    /// Whether this contact is verified (resolved via TDIP)
    pub verified: bool,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Timestamp when added
    pub added_at: u64,
}

impl Contact {
    /// Create a new contact with just a name and address.
    pub fn new(name: String, address: Address) -> Self {
        Self {
            name,
            address,
            did: None,
            notes: None,
            verified: false,
            tags: Vec::new(),
            added_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Set the TDIP DID.
    pub fn with_did(mut self, did: String) -> Self {
        self.did = Some(did);
        self
    }

    /// Set notes.
    pub fn with_notes(mut self, notes: String) -> Self {
        self.notes = Some(notes);
        self
    }

    /// Add a tag.
    pub fn with_tag(mut self, tag: String) -> Self {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
        self
    }

    /// Mark as verified.
    pub fn mark_verified(mut self) -> Self {
        self.verified = true;
        self
    }
}

/// Address book for managing contacts.
///
/// Supports:
/// - Adding/removing contacts by address
/// - Looking up contacts by name or address
/// - Tag-based filtering
/// - Persistent storage to JSON file
pub struct AddressBook {
    /// Contacts indexed by address
    contacts: DashMap<Address, Contact>,
    /// Name → address index for fast lookup
    name_index: DashMap<String, Address>,
    /// Optional storage path for persistence
    storage_path: Option<PathBuf>,
}

impl AddressBook {
    /// Create a new in-memory address book.
    pub fn new() -> Self {
        Self {
            contacts: DashMap::new(),
            name_index: DashMap::new(),
            storage_path: None,
        }
    }

    /// Create an address book with persistent storage.
    pub fn with_storage<P: AsRef<Path>>(path: P) -> Result<Self> {
        let storage_path = path.as_ref().to_path_buf();
        let book = Self {
            contacts: DashMap::new(),
            name_index: DashMap::new(),
            storage_path: Some(storage_path.clone()),
        };

        // Load existing contacts if file exists
        if storage_path.exists() {
            book.load()?;
        }

        Ok(book)
    }

    /// Add a contact to the address book.
    pub fn add_contact(&self, contact: Contact) -> Result<()> {
        // Check for duplicate name
        if self.name_index.contains_key(&contact.name) {
            let existing = self.name_index.get(&contact.name).unwrap();
            if *existing != contact.address {
                return Err(WalletError::Other(format!(
                    "Contact name '{}' already exists for a different address",
                    contact.name
                )));
            }
        }

        self.name_index
            .insert(contact.name.clone(), contact.address);
        self.contacts.insert(contact.address, contact);

        self.auto_save()?;
        Ok(())
    }

    /// Remove a contact by address.
    pub fn remove_contact(&self, address: &Address) -> Result<Option<Contact>> {
        if let Some((_, contact)) = self.contacts.remove(address) {
            self.name_index.remove(&contact.name);
            self.auto_save()?;
            Ok(Some(contact))
        } else {
            Ok(None)
        }
    }

    /// Get a contact by address.
    pub fn get_by_address(&self, address: &Address) -> Option<Contact> {
        self.contacts.get(address).map(|c| c.clone())
    }

    /// Get a contact by name.
    pub fn get_by_name(&self, name: &str) -> Option<Contact> {
        self.name_index
            .get(name)
            .and_then(|addr| self.contacts.get(&*addr).map(|c| c.clone()))
    }

    /// Resolve an address from a name (for easy sending).
    pub fn resolve_name(&self, name: &str) -> Option<Address> {
        self.name_index.get(name).map(|addr| *addr)
    }

    /// Search contacts by partial name match.
    pub fn search(&self, query: &str) -> Vec<Contact> {
        let query_lower = query.to_lowercase();
        self.contacts
            .iter()
            .filter(|entry| {
                let contact = entry.value();
                contact.name.to_lowercase().contains(&query_lower)
                    || contact
                        .notes
                        .as_ref()
                        .map(|n| n.to_lowercase().contains(&query_lower))
                        .unwrap_or(false)
                    || contact.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get all contacts with a specific tag.
    pub fn get_by_tag(&self, tag: &str) -> Vec<Contact> {
        self.contacts
            .iter()
            .filter(|entry| entry.value().tags.contains(&tag.to_string()))
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get all contacts.
    pub fn list_all(&self) -> Vec<Contact> {
        self.contacts
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get the number of contacts.
    pub fn count(&self) -> usize {
        self.contacts.len()
    }

    /// Update a contact's details.
    pub fn update_contact(
        &self,
        address: &Address,
        updater: impl FnOnce(&mut Contact),
    ) -> Result<()> {
        if let Some(mut entry) = self.contacts.get_mut(address) {
            let old_name = entry.name.clone();
            updater(&mut entry);

            // Update name index if name changed
            if entry.name != old_name {
                self.name_index.remove(&old_name);
                self.name_index.insert(entry.name.clone(), *address);
            }

            drop(entry);
            self.auto_save()?;
            Ok(())
        } else {
            Err(WalletError::Other(format!(
                "Contact not found for address {}",
                address
            )))
        }
    }

    /// Save contacts to persistent storage.
    pub fn save(&self) -> Result<()> {
        if let Some(ref path) = self.storage_path {
            let contacts: Vec<Contact> = self.list_all();
            let json = serde_json::to_string_pretty(&contacts)
                .map_err(|e| WalletError::SerializationError(e.to_string()))?;

            // Ensure parent directory exists
            if let Some(parent) = path.parent()
                && !parent.exists()
            {
                std::fs::create_dir_all(parent)?;
            }

            std::fs::write(path, json)?;
        }
        Ok(())
    }

    /// Load contacts from persistent storage.
    fn load(&self) -> Result<()> {
        if let Some(ref path) = self.storage_path
            && path.exists()
        {
            let json = std::fs::read_to_string(path)?;
            let contacts: Vec<Contact> = serde_json::from_str(&json)
                .map_err(|e| WalletError::SerializationError(e.to_string()))?;

            for contact in contacts {
                self.name_index
                    .insert(contact.name.clone(), contact.address);
                self.contacts.insert(contact.address, contact);
            }
        }
        Ok(())
    }

    /// Auto-save if storage path is configured.
    fn auto_save(&self) -> Result<()> {
        if self.storage_path.is_some() {
            self.save()?;
        }
        Ok(())
    }

    /// Clear all contacts.
    pub fn clear(&self) {
        self.contacts.clear();
        self.name_index.clear();
    }
}

impl Default for AddressBook {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_contact() {
        let book = AddressBook::new();
        let addr = Address::new([1u8; 32]);

        let contact = Contact::new("Alice".to_string(), addr)
            .with_did("did:tenzro:human:alice-123".to_string())
            .with_tag("friend".to_string());

        book.add_contact(contact).unwrap();

        let retrieved = book.get_by_address(&addr).unwrap();
        assert_eq!(retrieved.name, "Alice");
        assert_eq!(retrieved.did, Some("did:tenzro:human:alice-123".to_string()));
    }

    #[test]
    fn test_lookup_by_name() {
        let book = AddressBook::new();
        let addr = Address::new([1u8; 32]);

        book.add_contact(Contact::new("Bob".to_string(), addr)).unwrap();

        let resolved = book.resolve_name("Bob").unwrap();
        assert_eq!(resolved, addr);

        let contact = book.get_by_name("Bob").unwrap();
        assert_eq!(contact.address, addr);
    }

    #[test]
    fn test_duplicate_name_different_address() {
        let book = AddressBook::new();

        book.add_contact(Contact::new(
            "Alice".to_string(),
            Address::new([1u8; 32]),
        ))
        .unwrap();

        let result = book.add_contact(Contact::new(
            "Alice".to_string(),
            Address::new([2u8; 32]),
        ));

        assert!(result.is_err());
    }

    #[test]
    fn test_search() {
        let book = AddressBook::new();

        book.add_contact(
            Contact::new("Alice Validator".to_string(), Address::new([1u8; 32]))
                .with_tag("validator".to_string()),
        )
        .unwrap();

        book.add_contact(Contact::new(
            "Bob Provider".to_string(),
            Address::new([2u8; 32]),
        ))
        .unwrap();

        let results = book.search("alice");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Alice Validator");
    }

    #[test]
    fn test_get_by_tag() {
        let book = AddressBook::new();

        book.add_contact(
            Contact::new("V1".to_string(), Address::new([1u8; 32]))
                .with_tag("validator".to_string()),
        )
        .unwrap();

        book.add_contact(
            Contact::new("P1".to_string(), Address::new([2u8; 32]))
                .with_tag("provider".to_string()),
        )
        .unwrap();

        book.add_contact(
            Contact::new("V2".to_string(), Address::new([3u8; 32]))
                .with_tag("validator".to_string()),
        )
        .unwrap();

        let validators = book.get_by_tag("validator");
        assert_eq!(validators.len(), 2);
    }

    #[test]
    fn test_remove_contact() {
        let book = AddressBook::new();
        let addr = Address::new([1u8; 32]);

        book.add_contact(Contact::new("Alice".to_string(), addr)).unwrap();
        assert_eq!(book.count(), 1);

        let removed = book.remove_contact(&addr).unwrap();
        assert!(removed.is_some());
        assert_eq!(book.count(), 0);
        assert!(book.resolve_name("Alice").is_none());
    }

    #[test]
    fn test_update_contact() {
        let book = AddressBook::new();
        let addr = Address::new([1u8; 32]);

        book.add_contact(Contact::new("Alice".to_string(), addr)).unwrap();

        book.update_contact(&addr, |c| {
            c.notes = Some("Trusted validator".to_string());
            c.verified = true;
        })
        .unwrap();

        let updated = book.get_by_address(&addr).unwrap();
        assert_eq!(updated.notes, Some("Trusted validator".to_string()));
        assert!(updated.verified);
    }

    #[test]
    fn test_persistent_storage() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("contacts.json");

        // Create and save
        {
            let book = AddressBook::with_storage(&path).unwrap();
            book.add_contact(Contact::new(
                "Alice".to_string(),
                Address::new([1u8; 32]),
            ))
            .unwrap();
            book.add_contact(Contact::new(
                "Bob".to_string(),
                Address::new([2u8; 32]),
            ))
            .unwrap();
        }

        // Load and verify
        {
            let book = AddressBook::with_storage(&path).unwrap();
            assert_eq!(book.count(), 2);
            assert!(book.get_by_name("Alice").is_some());
            assert!(book.get_by_name("Bob").is_some());
        }
    }
}
