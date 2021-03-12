#![cfg_attr(not(feature = "std"), no_std)]
use codec::{Decode, Encode};
use frame_support::{ensure, traits::Currency, RuntimeDebug};
use frame_system::{ensure_none, ensure_root, ensure_signed};
#[cfg(feature = "std")]
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use sp_io::{crypto::secp256k1_ecdsa_recover, hashing::keccak_256};
use sp_runtime::transaction_validity::{
	InvalidTransaction, TransactionLongevity, TransactionSource, TransactionValidity,
	ValidTransaction,
};
use sp_std::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, Default, RuntimeDebug)]
pub struct EthereumAddress([u8; 20]);

#[cfg(feature = "std")]
impl Serialize for EthereumAddress {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
	{
		let hex: String = rustc_hex::ToHex::to_hex(&self.0[..]);
		serializer.serialize_str(&format!("0x{}", hex))
	}
}

#[cfg(feature = "std")]
impl<'de> Deserialize<'de> for EthereumAddress {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
		where
			D: Deserializer<'de>,
	{
		let base_string = String::deserialize(deserializer)?;
		let offset = if base_string.starts_with("0x") { 2 } else { 0 };
		let s = &base_string[offset..];
		if s.len() != 40 {
			Err(serde::de::Error::custom(
				"Bad length of Ethereum address (should be 42 including '0x')",
			))?;
		}
		let raw: Vec<u8> = rustc_hex::FromHex::from_hex(s)
			.map_err(|e| serde::de::Error::custom(format!("{:?}", e)))?;
		let mut r = Self::default();
		r.0.copy_from_slice(&raw);
		Ok(r)
	}
}

#[derive(Encode, Decode, Clone)]
pub struct EcdsaSignature(pub [u8; 65]);

impl PartialEq for EcdsaSignature {
	fn eq(&self, other: &Self) -> bool {
		&self.0[..] == &other.0[..]
	}
}

impl sp_std::fmt::Debug for EcdsaSignature {
	fn fmt(&self, f: &mut sp_std::fmt::Formatter<'_>) -> sp_std::fmt::Result {
		write!(f, "EcdsaSignature({:?})", &self.0[..])
	}
}

#[derive(Clone, Copy, PartialEq, Eq, Encode, Decode, RuntimeDebug)]
pub struct Message([u8; 256]);

/// The balance type of this module.
pub type BalanceOf<T> =
<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;


pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// Because this pallet emits events, it depends on the runtime's definition of an event.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		type Call: From<Call<Self>>;
		type Currency: Currency<Self::AccountId>;
	}
	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	pub struct Pallet<T>(_);

	#[pallet::storage]
	#[pallet::getter(fn message_state)]
	pub type MessageState<T: Config> = StorageMap<_, Blake2_128Concat, Message, bool>;

	#[pallet::event]
	#[pallet::metadata(T::AccountId = "AccountId", BalanceOf<T> = "Balance")]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config>{
		MessageVerified(T::AccountId, Message, bool),
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The message signature is invalid.
		InvalidSignature,
		/// The signer of message is invalid.
		InvalidSigner,
		/// The message has been verified
		MessageAlreadyVerified,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::weight(0 + T::DbWeight::get().reads_writes(1,1))]
		pub fn verify_message(
			origin: OriginFor<T>,
			account: T::AccountId,
			message: Message,
			signature: EcdsaSignature
		) -> DispatchResultWithPostInfo {
			let _ = ensure_none(origin)?;
			ensure!(MessageState::<T>::get(&message).is_some(), Error::<T>::MessageAlreadyVerified);
			let address = Encode::encode(&account);
			let signer = Self::eth_recover(&signature, &address, &message.0)
				.ok_or(Error::<T>::InvalidSignature)?;
			// TODO: Verify message signature
			// ensure!(signer == message signer, Error::<T>::InvalidSigner);
			Self::deposit_event(Event::MessageVerified(account, message, true));
			Ok(().into())
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	impl<T: Config> Pallet<T> {
		// Constructs the message that Ethereum RPC's `personal_sign` and `eth_sign` would sign.
		fn ethereum_signable_message(what: &[u8], extra: &[u8]) -> Vec<u8> {
			let mut l = what.len() + extra.len();
			let mut rev = Vec::new();
			while l > 0 {
				rev.push(b'0' + (l % 10) as u8);
				l /= 10;
			}
			let mut v = b"\x19Ethereum Signed Message:\n".to_vec();
			v.extend(rev.into_iter().rev());
			v.extend_from_slice(what);
			v.extend_from_slice(extra);
			v
		}

		// Attempts to recover the Ethereum address from a message signature signed by using
		// the Ethereum RPC's `personal_sign` and `eth_sign`.
		fn eth_recover(s: &EcdsaSignature, what: &[u8], extra: &[u8]) -> Option<EthereumAddress> {
			let msg = keccak_256(&Self::ethereum_signable_message(what, extra));
			let mut res = EthereumAddress::default();
			res.0
				.copy_from_slice(&keccak_256(&secp256k1_ecdsa_recover(&s.0, &msg).ok()?[..])[12..]);
			Some(res)
		}
	}

	impl<T: Config> frame_support::unsigned::ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			const PRIORITY: u64 = 100;

			let (maybe_signer, tx_hash) = match call {
				Call::verify_message(account, message, eth_signature) => {
					let address = Encode::encode(&account);
					(
						Self::eth_recover(&eth_signature, &address, &message.0),
						message,
					)
				}
				_ => return Err(InvalidTransaction::Call.into()),
			};

			let signer = maybe_signer.ok_or(InvalidTransaction::BadProof)?;

			Ok(ValidTransaction {
				priority: PRIORITY,
				requires: vec![],
				provides: vec![("claims", signer).encode()],
				longevity: TransactionLongevity::max_value(),
				propagate: true,
			})
		}
	}
}

#[repr(u8)]
pub enum ValidityError {
	/// The message signature is invalid.
	InvalidSignature = 0,
	/// The signer of message is invalid.
	InvalidSigner = 1,
	/// The message has been validated
	MessageAlreadyValidated = 2,
}

impl From<ValidityError> for u8 {
	fn from(err: ValidityError) -> Self {
		err as u8
	}
}
