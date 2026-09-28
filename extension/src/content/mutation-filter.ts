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
    const changedNodes = [...record.addedNodes, ...record.removedNodes];
    return changedNodes.length === 0 || changedNodes.some((node) => !isOwnedNode(node, ownedNodes));
  });
}
