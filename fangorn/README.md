# Fangorn

Fangorn is the core protocol that enables practical witness encryption.

## Node Architecture

## Node Setup Protocol

### RPC

## **RPC Methods**

| Method               | Request Type              | Response Type              | Description                                                                                               |
| -------------------- | ------------------------- | -------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Preprocess**       | `PreprocessRequest`       | `PreprocessResponse`       | Requests encryption and aggregation keys (system key) from a node for setup.                              |
| **Partdec**          | `PartDecRequest`          | `PartDecResponse`          | Requests a partial decryption from a node for a given ciphertext/witness.                                 |

---

## **Message Types**

### **PreprocessRequest**

| Field    | Type | Description                                             |
| -------- | ---- | ------------------------------------------------------- |
| *(none)* | —    | Empty request used to request preprocessing parameters. |

### **PreprocessResponse**

| Field                    | Type     | Description                                                             |
| ------------------------ | -------- | ----------------------------------------------------------------------- |
| `hex_serialized_sys_key` | `string` | The hex-encoded serialized system key (aggregation/encryption context). |

---

### **PartDecRequest**

| Field         | Type     | Description                                                          |
| ------------- | -------- | -------------------------------------------------------------------- |
| `filename`    | `string` | Identifier for the ciphertext stored remotely (e.g., IPFS filename). |
| `witness_hex` | `string` | Hex-encoded witness used for partial decryption.                     |

### **PartDecResponse**

| Field                       | Type     | Description                                           |
| --------------------------- | -------- | ----------------------------------------------------- |
| `hex_serialized_decryption` | `string` | The node's partial decryption in hex-serialized form. |

---

If you want, I can also generate the tables for `AggregateDecryptRequest` and `AggregateDecryptResponse` once you define their fields.
