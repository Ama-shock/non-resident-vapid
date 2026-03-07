/* tslint:disable */
/* eslint-disable */

export function __wbg_set_wasm(val: WebAssembly.Exports): void;

export function decode_credential_bundle_wasm(
	bundle_base64url: string,
	key_id_base64url: string,
	private_key_base64url: string,
): any;

export function encode_credential_bundle_wasm(
	subscription_json: string,
	key_id_base64url: string,
	public_key_base64url: string,
	expiration_sec: bigint,
): string;
