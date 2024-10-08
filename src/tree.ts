/*
This is a partial version of matrix.org's lbbtree.ts in mls-ts:
https://gitlab.matrix.org/matrix-org/mls-ts/-/blob/develop/src/lbbtree.ts

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


export class Leaf<T> {
  constructor(public readonly data: T) {}
}

export class Internal<T> {
  constructor(
      public readonly data: T,
      public readonly leftChild: Leaf<T> | Internal<T>,
      public readonly rightChild: Leaf<T> | Internal<T>,
  ) {}
}

export type Node<T> = Leaf<T> | Internal<T>;

function depth(size: number): number {
  return Math.floor(Math.log2(2*size - 1));
}

class NodeIterator<T> implements Iterator<T> {
  private path: Node<T>[];
  private dirs: number[];
  constructor(private root: Node<T>) {
      this.path = [root];
      this.dirs = [];
      this.pushLeftPath(root);
  }
  private pushLeftPath(start: Node<T>): void {
      for (let cur = start; cur instanceof Internal;) {
          cur = cur.leftChild;
          this.path.push(cur);
          this.dirs.push(-1)
      }
  }
  next(): IteratorResult<T> {
      if (this.path.length === 0) {
          // we've iterated through the whole tree
          return {done: true, value: undefined};
      } else if (this.dirs.length === 0) {
          // special cases where the root is a leaf node
          const node = this.path.pop()!;
          return {done: false, value: node.data};
      }

      const lastdir = this.dirs.pop()!;
      switch (lastdir) {
          case -1:
          {
              const node = this.path.pop()!;
              this.dirs.push(0);
              return {done: false, value: node.data};
          }
          case 0:
          {
              const node = this.path[this.path.length - 1]!;
              this.dirs.push(1);
              const rightChild = (node as Internal<T>).rightChild;
              this.path.push(rightChild);
              this.pushLeftPath(rightChild);
              return {done: false, value: node.data};
          }
          case 1:
          {
              const node = this.path.pop()!;
              this.path.pop();
              while (this.dirs.length !== 0 && this.dirs.pop() === 1)
                this.path.pop();
              if (this.path.length !== 0) this.dirs.push(0);
              return {done: false, value: node.data};
          }
      }
      
      // This shouldn't happen, but just in case
      return {done: true, value: undefined};
  }
}

export class Tree<T> implements Iterable<T> {
  readonly size: number; // the number of leaf nodes
  readonly root: Node<T>;
  constructor(data: T[]) {
    const length = data.length;
    if (length % 2 !== 1) throw new Error("Must have an odd number of nodes");
    this.size = (length + 1) / 2;
    this.root = this.#partialTree(data as T[], 0, length);
  }

  [Symbol.iterator]() {
      return new NodeIterator<T>(this.root);
  }

  // build a (possibly) partial tree from an array of data
  #partialTree(data: T[], start: number, finish: number): Node<T> {
      const numNodes = finish - start;
      if (numNodes == 1) return new Leaf<T>(data[start]!);
      if (numNodes < 0) throw new Error("Invalid node amount");

      const numLeaves = (numNodes + 1) / 2;
      const d = depth(numLeaves);
      const numLeftTreeLeaves = 1 << (d-1);
      const numLeftTreeNodes = 2*numLeftTreeLeaves - 1;

      const leftChild: Node<T> = this.#completeTree(
          data, start, start + numLeftTreeNodes,
      );
      const rightChild: Node<T> = this.#partialTree(
          data, start + numLeftTreeNodes + 1, finish,
      );
      return new Internal<T>(data[start + numLeftTreeNodes]!, leftChild, rightChild);
  }

  // build a complete tree from an array of data
  #completeTree(data: T[], start: number, finish: number): Node<T> {
      const numNodes = finish - start;
      if (numNodes == 1) return new Leaf<T>(data[start]!);

      const subTreeSize = (numNodes - 1) >> 1;

      const leftChild: Node<T> = this.#completeTree(
          data, start, start + subTreeSize,
      );
      const rightChild: Node<T> = this.#completeTree(
          data, start + subTreeSize + 1, finish,
      );
      return new Internal<T>(data[start + subTreeSize]!, leftChild, rightChild);
  }
}