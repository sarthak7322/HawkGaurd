export interface MutationChange {
  target: Node;
  addedNodes: Iterable<Node>;
  removedNodes: Iterable<Node>;
}

function isOwnedNode(node: Node, ownedNodes: WeakSet<Node>): boolean {
  let current: Node | null = node;
  while (current) {
    if (ownedNodes.has(current)) return true;
    current = current.parentNode;
  }
  return false;
}

export function shouldRescanForMutations(
  records: readonly MutationChange[],
  ownedNodes: WeakSet<Node>,
): boolean {
  return records.some((record) => {
    if (isOwnedNode(record.target, ownedNodes)) return false;
    let hasChangedNodes = false;
    for (const node of record.addedNodes) {
      hasChangedNodes = true;
      if (!isOwnedNode(node, ownedNodes)) return true;
    }
    for (const node of record.removedNodes) {
      hasChangedNodes = true;
      if (!isOwnedNode(node, ownedNodes)) return true;
    }
    return !hasChangedNodes;
  });
}
