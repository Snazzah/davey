export const DAVE_PROTOCOL_VERSION = 1;

export enum CipherSuite { // u16
  MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 2
};

/** @see https://www.iana.org/assignments/mls/mls.xhtml#mls-extension-types */
export enum ExtensionType { // u16
  APPLICATION_ID = 1,
  RATCHET_TREE = 2,
  REQUIRED_CAPABILITIES = 3,
  EXTERNAL_PUB = 4,
  EXTERNAL_SENDERS = 5,
};

/** @see https://www.iana.org/assignments/mls/mls.xhtml#mls-credential-types */
export enum CredentialType { // u16
  BASIC = 1,
  X509 = 2,
};

export enum ProtocolVersion { // u16
  MLS10 = 1,
};

export enum LeafNodeSource { // u8
  KEY_PACKAGE = 1,
  UPDATE = 2,
  COMMIT = 3,
};

/** @see https://www.iana.org/assignments/mls/mls.xhtml#mls-proposal-types */
export enum ProposalType { // u16
  ADD = 1,
  UPDATE = 2,
  REMOVE = 3,
  PSK = 4,
  REINIT = 5,
  EXTERNAL_INIT = 6,
  GROUP_CONTEXT_EXTENSIONS = 7,
};

/** @see https://daveprotocol.com/#dave_mls_proposals-27 */
export enum ProposalsOperationType { // u16
  APPEND = 0,
  REVOKE = 1,
};

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-8.4 */
export enum PSKType { // u8
  EXTERNAL = 1,
  RESUMPTION = 2,
};

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-8.4 */
export enum ResumptionPSKUsage { // u8
  APPLICATION = 1,
  REINIT = 2,
  BRANCH = 3,
};

/** @see https://www.iana.org/assignments/mls/mls.xhtml#mls-wire-formats */
export enum WireFormat { // u16
  MLS_PUBLIC_MESSAGE = 1,
  MLS_PRIVATE_MESSAGE = 2,
  MLS_WELCOME = 3,
  MLS_GROUP_INFO = 4,
  MLS_KEY_PACKAGE = 5,
};

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-6-4 */
export enum ContentType { // u8
  APPLICATION = 1,
  PROPOSAL = 2,
  COMMIT = 3,
};

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-6-4 */
export enum SenderType { // u8
  MEMBER = 1,
  EXTERNAL = 2,
  NEW_MEMBER_PROPOSAL = 3,
  NEW_MEMBER_COMMIT = 4,
};

export enum ProposalOrRefType { // u8
  PROPOSAL = 1,
  REFERENCE = 2,
};

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8-5 */
export enum NodeType { // u8
  LEAF = 1,
  PARENT = 2,
};