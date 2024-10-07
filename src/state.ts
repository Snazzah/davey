import type { DAVESession } from "./session";
import { refHash, verifyWithLabel, type DataCursor } from "./util";
import { CipherSuite, ContentType, CredentialType, LeafNodeSource, ProposalType, ProtocolVersion, SenderType, WireFormat } from "./util/constants";

export class MLSState {
  epoch = 0n;

  // Normally states have their own ciphersuite, group id, leafnode, and keys, but we *may* not need that
  constructor(private session: DAVESession) {}

  // TODO form mls message

  // TODO createGroupContext
  createGroupContext() {

  }

  // TODO pass recognized user IDs
  async parseMLSMessageProposal(cursor: DataCursor) {
    const protocolVersion: ProtocolVersion = cursor.readU16();
    const wireFormat: WireFormat = cursor.readU16();
  
    if (protocolVersion !== ProtocolVersion.MLS10)
      throw new Error(`Unsupported protocol version: ${protocolVersion}`);
  
    if (wireFormat !== WireFormat.MLS_PUBLIC_MESSAGE)
      throw new Error(`Unsupported wire format: ${wireFormat}`);

    const groupId = cursor.readVector();
    const epoch = cursor.readU64();

    const groupIdMatches = !this.session.groupId.find((v, i) => groupId[i] !== v);
    if (!groupIdMatches) throw new Error('Public message is not for this group');
    if (this.epoch !== epoch) throw new Error(`Public message is not for this epoch (${this.epoch} != ${epoch})`);

    const senderType: SenderType = cursor.readU8();
    const senderIndex = cursor.readU32();

    if (senderType !== SenderType.EXTERNAL) throw new Error('MLS proposal is not from external sender');

    const authenticatedData = cursor.readVector();
    const contentType: ContentType = cursor.readU8();

    if (contentType !== ContentType.PROPOSAL) throw new Error('parseMLSMessageProposal called with a non-proposal message');

    // Parsing proposal
    const proposalType: ProposalType = cursor.readU16();

    if (proposalType !== ProposalType.ADD && proposalType !== ProposalType.REMOVE)
      throw new Error(`MLS proposal must be add or remove (${proposalType})`);

    const { credentialIdentity } = await this.#validateKeyPackage(cursor);

    const auth = cursor.readVector();

    // TODO on add, check against list of recognized user IDs in credentialIdentity
  }

  async #validateKeyPackage(cursor: DataCursor) {
    const startIndex = cursor.index;
    const protocolVersion: ProtocolVersion = cursor.readU16();
    if (protocolVersion !== ProtocolVersion.MLS10)
      throw new Error(`Unsupported protocol version in key package: ${protocolVersion}`);

    const ciphersuite: CipherSuite = cursor.readU16();
    if (ciphersuite !== this.session.ciphersuite)
      throw new Error(`Unexpected cipher suite in key package: ${ciphersuite}`);

    const initKey = cursor.readVector();
    const { signatureKey, credentialIdentity } = await this.#validateLeafNode(cursor);
    const extensions = cursor.readVector();
    const endIndex = cursor.index;
    const signature = cursor.readVector();

    const verified = await verifyWithLabel(
      signatureKey, 'KeyPackageTBS', signature, cursor.buffer.subarray(startIndex, endIndex)
    );
    if (!verified) throw new Error('Key package not verified');

    const ref = refHash('sha256', 'MLS 1.0 KeyPackage Reference', cursor.buffer.subarray(startIndex, cursor.index));
    return { credentialIdentity, ref };
  } 

  async #validateLeafNode(cursor: DataCursor) {
    const startIndex = cursor.index;
    const encryptionKey = cursor.readVector();
    const signatureKey = cursor.readVector();

    const credentialType = cursor.readU16();
    const credentialIdentity = cursor.readVector();

    this.#validateCapabilities(cursor);

    const leafNodeSource: LeafNodeSource = cursor.readU8();

    if (leafNodeSource !== LeafNodeSource.KEY_PACKAGE)
      throw new Error('Leaf node source is not key package');

    const notBefore = cursor.readU64();
    const notAfter = cursor.readU64();
    const extensions = cursor.readVector();
    const endIndex = cursor.index;
    const signature = cursor.readVector();

    const verified = await verifyWithLabel(
      signatureKey, 'LeafNodeTBS', signature, cursor.buffer.subarray(startIndex, endIndex)
    );
    if (!verified) throw new Error('Leaf node not verified');

    return { signatureKey, credentialIdentity };
  }

  #validateCapabilities(cursor: DataCursor) {
    const capabilitiesVersions = cursor.readVector();
    const capabilitiesCipherSuites = cursor.readVector();
    const capabilitiesExtensions = cursor.readVector();
    const capabilitiesProposals = cursor.readVector();
    const capabilitiesCredentials = cursor.readVector();

    if (capabilitiesVersions.length !== 2 || capabilitiesVersions.readInt16BE() !== ProtocolVersion.MLS10)
      throw new Error('Unexpected versions in leaf node capabilities');

    if (capabilitiesCipherSuites.length !== 2 || capabilitiesCipherSuites.readInt16BE() !== this.session.ciphersuite)
      throw new Error('Unexpected cipher suites in leaf node capabilities');

    if (capabilitiesCredentials.length !== 2 || capabilitiesCredentials.readInt16BE() !== CredentialType.BASIC)
      throw new Error('Unexpected credentials in leaf node capabilities');
  }
}