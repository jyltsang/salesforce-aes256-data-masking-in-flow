# salesforce-aes256-data-masking-in-flow

The script template offers a Salesforce admin-configurable utility designed for Salesforce Flows. It is an automated, native solution built to protect Personal Information (PI) within Salesforce environments by masking values in the user interface to prevent visual exposure and securely capturing tamper-evident audit logs. 

It bridges the compliance and security gap where standard Salesforce record layouts do not encrypt data at rest on the record UI, which creates severe operational risks for insider threats and data leakage.

## Risks Mitigated

* **Insider Threat & Accidental Exposure (Data Minimization):** Limits viewing of unnecessary PI directly at the record level to protect data privacy and minimize accidental data visibility.
* **Malicious Data Export Prevention:** Mitigates the risk of insider data exfiltration or malicious actors leveraging compromised credentials or connected third-party loaders to bulk export unencrypted production data.
* **Regulatory Non-Compliance:** Directly addresses compliance mandates (e.g., GDPR Article 32 - Security of Processing) by ensuring sensitive field data is cryptographically protected via symmetric encryption.

## Limitation
_Please be aware that this encryption method is AES-256, which is symmetric encryption. The key is saved within the script, so if an attacker is able to export the metadata, they can use the key to decrypt the data._

---

## Implementation & Setup

### 1. Preparation & AES-256 Key Generation

Before deploying or running the Apex classes, you must generate a cryptographically secure key meeting exact specifications:

* **Algorithm:** Advanced Encryption Standard (AES) operating with a **256-bit key length** (`AES256`).
* **Byte Length Requirement:** A 256-bit key requires **exactly 32 bytes** of raw binary data.
* **Encoding Format:** Salesforce's `EncodingUtil.base64Decode()` expects the 32-byte key encoded as a **Base64 string** (resulting in a 44-character string).

#### Generating a Key via OpenSSL:
1. Run the following command in your terminal:
   ```bash
   openssl rand -base64 32```
   ```
The result should give you a 44-character string, 256-bit key 

2. Copy the generated string and paste it into the `DEFAULT_AES_KEY` constant variable at the top of both Apex scripts:
   ```apex 
   private static final String DEFAULT_AES_KEY = 'YOUR_GENERATED_BASE64_KEY_HERE';
   ```

### 2. Create Necessary Salesforce Fields

To store the encrypted values and track status, create the following fields on your target object (e.g., Contact):
* **Encrypted Log Field:** Text Area (Rich) maximised to **131,072 characters** to store the complete audit logs (capable of holding logs for up to 400 fields).
* **Status Checkbox Field:** Checkbox field to track whether the record is currently masked.

### 3. Deploy Apex Classes

Deploy both `FlowAESDataMaskingAction.apxc` and `FlowAESDataUnmaskingAction.apxc` into your Salesforce environment via Developer Console or VS Code.

---

### 4. Create Flow

These are invocable actions, so you can freely use them in a Flow. You need to get the record collection, then add the API names to a text collection in an assignment. Afterward, you can use the action and assign the corresponding variables. Here are more details:

#### For masking (`FlowAESDataMaskingAction.apxc`): 
Please create a flow to get all targeted records you would like to encrypt, use an assignment to add all the fields that you want to encrypt, and add an action to include the following values:
  1. **Object** (Collection of SObjects)
  2. **Fields Name** (Collection of Text API names)
  3. **Log Field** (Text Area/Rich Text API name for audit logs)
  4. **Checkbox Field** (Status Checkbox API name, e.g., `Data_Masked__c`)

#### For unmasking (`FlowAESDataUnmaskingAction.apxc`):
Similar to masking, but you do not need to specify individual fields for unmasking, as the masked values are already noted in the target fields; it will automatically restore the data.
  1. **Object** (Collection of SObjects)
  2. **Log Field** (Text Area/Rich Text API name storing audit logs)
  3. **Checkbox Field** (Status Checkbox API name to reset)
