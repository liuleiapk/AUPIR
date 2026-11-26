"""Client-only normalization; output is a linear reference list, not a new DSL.

Atoms are (column,bits,GT_threshold,GT_beta,LT_threshold,LT_beta,constant).
Gates are (delta,left_reference,right_reference); delta is private until shared.
"""
from __future__ import annotations

RELATIONS = frozenset(('GT', 'GE', 'LT', 'LE', 'EQ', 'NE'))


def _literal(node, fields):
    if not isinstance(node, (tuple, list)) or not node:
        raise ValueError('predicate node')
    if node[0] not in RELATIONS:
        return None
    if len(node) != 3 or node[1] not in fields:
        raise ValueError('condition field/arity')
    op, field, target = node
    bits = fields[field]['bits']
    if not isinstance(bits, int) or not 1 <= bits <= 32:
        raise ValueError('public unsigned field width')
    if type(target) is not int or not 0 <= target < (1 << bits):
        raise ValueError('private value outside public unsigned domain')
    return op, field, bits, target


def _constant(value):
    # Both zero-payload keys must still be generated and evaluated.
    return 0, 0, 0, 0, int(value)


def relation_slots(op, t, bits):
    """GT slot first, LT slot second, neither input domain is widened."""
    upper = (1 << bits) - 1
    if (op == 'GT' and t == upper) or (op == 'LT' and t == 0):
        return _constant(0)
    if (op == 'GE' and t == 0) or (op == 'LE' and t == upper):
        return _constant(1)
    return {
        'GT': (t, 1, 0, 0, 0),
        'GE': (0, 0, t, 1, 1),
        'LT': (0, 0, t, 1, 0),
        'LE': (t, 1, 0, 0, 1),
        'EQ': (t, 1, t, 1, 1),
        'NE': (t, 1, t, 1, 0),
    }[op]


def interval_slots(lower, upper, lower_open, upper_open, bits):
    """Convert two in-domain endpoints to [A,B], checking before adjustment."""
    maximum = (1 << bits) - 1
    if lower > upper or (lower_open and lower == maximum) or (upper_open and upper == 0):
        return _constant(0)
    a = lower + int(lower_open)
    b = upper - int(upper_open)
    if a > b:
        return _constant(0)
    if a == 0 and b == maximum:
        return _constant(1)
    return b, 1, a, 1, 1


def _interval(node, fields):
    # Fuse existing AND(lower-bound,upper-bound) syntax, in either order.
    if node[0] != 'AND' or len(node) != 3:
        return None
    left, right = _literal(node[1], fields), _literal(node[2], fields)
    if left is None or right is None or left[1] != right[1]:
        return None
    if left[0] in ('LT', 'LE'):
        left, right = right, left
    if left[0] not in ('GT', 'GE') or right[0] not in ('LT', 'LE'):
        return None
    _, field, bits, lower = left
    return field, bits, interval_slots(lower, right[3], left[0] == 'GT', right[0] == 'LT', bits)


def compile_query(expr, fields):
    atoms, gates = [], []
    columns = {field: i for i, field in enumerate(fields)}

    def atom(field, bits, slots, negate):
        gt, a, lt, b, constant = slots
        ref = len(atoms)
        atoms.append((columns[field], bits, gt, a, lt, b, constant ^ int(negate)))
        return ('a', ref)

    def walk(node, negate=False):
        literal = _literal(node, fields)
        if literal is not None:
            op, field, bits, target = literal
            return atom(field, bits, relation_slots(op, target, bits), negate)
        op = node[0]
        if op == 'NOT':
            if len(node) != 2:
                raise ValueError('NOT arity')
            return walk(node[1], not negate)
        if op not in ('AND', 'OR') or len(node) != 3:
            raise ValueError('only AND/OR/NOT connectors are supported')
        fused = _interval(node, fields)
        if fused is not None:
            return atom(*fused, negate)
        # De Morgan flips each child polarity and the binary connector, without
        # copying any references or adding runtime NOT gates.
        a, b = walk(node[1], negate), walk(node[2], negate)
        delta = int(op == 'OR') ^ int(negate)
        ref = len(gates)
        gates.append((delta, a, b))
        return ('g', ref)

    walk(expr)
    count = len(atoms)
    reference = lambda item: item[1] if item[0] == 'a' else count + item[1]
    return atoms, [(delta, reference(a), reference(b)) for delta, a, b in gates]


def public_template(n, field_count, atoms, gates, width=128):
    return (f'IPBM2 {n} {field_count} {len(atoms)} {len(gates)} {width}\n'
            + ''.join(f'{column} {bits}\n' for column, bits, *_ in atoms)
            + ''.join(f'{a} {b}\n' for _, a, b in gates))


def private_spec(atoms, gates):
    return (f'{len(atoms)} {len(gates)}\n'
            + ''.join(' '.join(map(str, atom)) + '\n' for atom in atoms)
            + ''.join(f'{a} {b} {delta}\n' for delta, a, b in gates))
