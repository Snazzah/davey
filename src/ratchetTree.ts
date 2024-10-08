/*
This is a modified version of matrix.org's ratchettree.ts in mls-ts:
https://gitlab.matrix.org/matrix-org/mls-ts/-/blob/develop/src/ratchettree.ts

Copyright 2020 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import { Internal, Node, Tree } from "./tree";
import { DataCursor, hash } from "./util";
import { CipherSuite } from "./util/constants";
import { Resolvable, serializeResolvers } from "./util/serialize";
import * as treemath from "./util/treemath";

/* Each node in a ratchet tree contains up to five values:
 *
 * - A private key (only within the member's direct path, see below)
 * - A public key
 * - An ordered list of leaf indices for "unmerged" leaves (see {{views}})
 * - A credential (only for leaf nodes)
 * - A hash of the node's parent, as of the last time the node was changed.
 *
 * We also add a leaf number, when the node represents a leaf.
 */

export class NodeData {
  constructor(
    public privateKey: Uint8Array | undefined,
    public publicKey: Uint8Array | undefined,
    public unmergedLeaves: number[],
    public credential: Uint8Array | undefined,
    public parentHash: Uint8Array | undefined,
    public leafNum?: number | undefined,
  ) {}

  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.1 */
  toParentNodeResolvers() {
    return [
      ['v', this.publicKey],                                 // encryption_key
      ['v', this.parentHash],                                // parent_hash
      ['v', this.unmergedLeaves.map((ln) => (['u32', ln]))], // unmerged_leaves
    ] as Resolvable[];
  }
}

export class MinimalKeyPackage {
  credentialIdentity: Buffer;
  constructor(
    public leafnode: Buffer
  ) {
    const cursor = new DataCursor(leafnode.length, leafnode);
    // encryption_key, signature_key, credential_type
    cursor.skip(['v', 'v', 'u8']);
    this.credentialIdentity = cursor.readVector();
  }
}

export class RatchetTree {
  readonly idToLeafNum: Map<string, number>;
  readonly emptyLeaves: number[];
  readonly nodeHashes: Record<number, Buffer>;

  constructor(
    readonly ciphersuite: CipherSuite,
    readonly leafNum: number,
    readonly tree: Tree<NodeData>,
    readonly keyPackages: MinimalKeyPackage[],
  ) {
    this.idToLeafNum = new Map(
      [...tree]
        .filter((val, idx) => !(idx % 2))
        .map((val, idx): [string, number] | undefined => {
          if (val.credential) return [val.credential.toString(), idx];
          else return undefined;
        })
        .filter(val => val !== undefined),
    );
    this.emptyLeaves = 
      [...tree]
        .filter((val, idx) => !(idx % 0))
        .map((val, idx): [NodeData, number] => [val, idx])
        .filter(v => v[0].publicKey === undefined)
        .map(v => v[1]);
    this.nodeHashes = {};
  }

  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8 */
  #calculateNodeHash(nodeNum: number, node: Node<NodeData>) {
    if (!(nodeNum in this.nodeHashes)) {
      let data: Buffer;
      const parentNode = (nodeNum & 0x1) === 1;

      if (parentNode) {
        // ParentNodeHashInput
        data = serializeResolvers([
          ['u32', nodeNum],
          ...(node.data.publicKey ? [
            ['u8', 1],
            ...node.data.toParentNodeResolvers()
          ] : [
            ['u8', 0]
          ]) as Resolvable[],
          ['v', 
            this.#calculateNodeHash(
              treemath.left(nodeNum),
              (node as Internal<NodeData>).leftChild,
            )!
          ],
          ['v', 
            this.#calculateNodeHash(
              treemath.right(nodeNum, this.tree.size),
              (node as Internal<NodeData>).rightChild,
            )!
          ]
        ]);
      } else {
        // LeafNodeHashInput
        data = serializeResolvers([
          ['u32', nodeNum],
          ...(node.data.publicKey ? [
            ['u8', 1],
            this.keyPackages[nodeNum / 2]!.leafnode
          ] : [
            ['u8', 0]
          ]) as Resolvable[]
        ]);
      }
      this.nodeHashes[nodeNum] = hash('sha256', data);
    }
    return this.nodeHashes[nodeNum]!;
  }

  /** @see https://www.rfc-editor.org/rfc/rfc9420.html#section-7.8 */
  calculateTreeHash() {
    return this.#calculateNodeHash(treemath.root(this.tree.size), this.tree.root);
  }
}