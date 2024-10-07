import { p256 } from '@noble/curves/p256';
import { CredentialType, ProtocolVersion, CipherSuite, LeafNodeSource, WireFormat, SenderType, ContentType, ProposalOrRefType } from './constants';
import { serializeResolvers } from './serialize';
import { rawToPKCS8, signWithLabel } from '.';

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.2-2 */
export async function serializeLeafNode(
  ciphersuite: CipherSuite,
  encryptionKey: Uint8Array,
  signatureKey: Uint8Array,
  userId: string,
  signingPrivateKey: Uint8Array
) {
  const content = serializeResolvers([
    ['v', encryptionKey], // encryption_key
    ['v', signatureKey],  // signature_key

    // credential
    ['u16', CredentialType.BASIC],    // credential_type
    ['v', [['u64', BigInt(userId)]]], // identity (user_id)

    // capabilities
    ['v', [['u16', ProtocolVersion.MLS10]]],  // versions
    ['v', [['u16', ciphersuite]]],            // cipher_suites
    ['v', ], // extensions
    ['v', ], // proposals
    ['v', [['u16', CredentialType.BASIC]]], // credentials

    ['u8', LeafNodeSource.KEY_PACKAGE], // leaf_node_source

    // lifetime
    ['u64', 0n], // not_before
    ['u64', 0xFFFFFFFFFFFFFFFFn], // not_after

    ['v', ], // extensions
    // signature (appended later)
  ]);

  const signature = await signWithLabel(rawToPKCS8(signingPrivateKey), 'LeafNodeTBS', content);
  return Buffer.concat([content, serializeResolvers([['v', signature]])]);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-10-6 */
export async function serializeKeyPackage(
  ciphersuite: CipherSuite,
  initKey: Uint8Array,
  leafnode: Buffer,
  signingPrivateKey: Uint8Array
) {
  const content = serializeResolvers([
    ['u16', ProtocolVersion.MLS10], // protocol_version
    ['u16', ciphersuite],           // cipher_suite
    ['v', initKey],                 // init_key
    leafnode,                       // leafnode
    ['v'],                          // extensions
    // signature (appended later)
  ]);

  const signature = await signWithLabel(rawToPKCS8(signingPrivateKey), 'KeyPackageTBS', content);
  return Buffer.concat([content, serializeResolvers([['v', signature]])]);
}

/** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-6-4 */
export async function serializeMLSCommitMessage(groupId: Uint8Array, epoch: bigint, leafIndex: number, proposalRefs: Uint8Array[]) {
  const framedContent = serializeResolvers([
    groupId,        // group_id
    ['u64', epoch], // epoch

    // sender
    ['u16', SenderType.MEMBER], // sender_type
    ['u32', leafIndex],         // leaf_index

    ['v'],                      // authenticated_data
    ['u8', ContentType.COMMIT], // content_type

    // commit
    ['v', // proposals
      // this turns all proposalRefs into ProposalOrRefs in the RFC
      proposalRefs.map((ref) => ([
        ['u8', ProposalOrRefType.REFERENCE] as ['u8', number],
        ['v', ref]  as ['v', Uint8Array]
      ])).reduce((p, v) => [...p, ...v])
    ],
    ['v'], // path (technically an optional, but an empty vector works the same)
  ]);

  // https://www.rfc-editor.org/rfc/rfc9420.html#section-6.1-2
  const framedContentTBS = serializeResolvers([
    ['u16', ProtocolVersion.MLS10],          // protocol_version
    ['u16', WireFormat.MLS_PUBLIC_MESSAGE],  // wire_format
    framedContent,                           // content
    // TODO group_context [https://www.rfc-editor.org/rfc/rfc9420.html#section-8.1]
  ]);

  const content = serializeResolvers([
    ['u16', ProtocolVersion.MLS10],          // protocol_version
    ['u16', WireFormat.MLS_PUBLIC_MESSAGE],  // wire_format
    
    // public_message
    // content
  ]);
}