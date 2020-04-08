from io import StringIO
from unittest import TestCase, skip

from op import *
from script import Script


class MiniScript:
    def __init__(self, word, parent, modifiers, children=None):
        self.word = word
        self.parent = parent
        self.modifiers = modifiers or ''
        self.children = children or []
        if parent:
            self.parent.children.append(self)
        if children:
            for child in children:
                child.parent = self
        self.type = None

    def __repr__(self):
        if self.modifiers:
            result = f'{self.modifiers}:{self.word}'
        else:
            result = f'{self.word}'
        if self.children:
            children = ','.join([f'{i}' for i in self.children])
            return f'{result}({children})'
        else:
            return result

    @classmethod
    def from_script(cls, items, parent=None):
        '''The array items will be used destructively'''
        node = None
        last_length = len(items)
        if len(items) > 4 and is_number_op_code(items[0]) \
           and len(items[1]) == 33:
            node = cls('multi', parent, None)
            cls(str(op_code_to_number(items[0])), node, None)
            items.pop(0)
            while len(items[0]) == 33:
                cls(items[0].hex(), node, None)
                items.pop(0)
            n = len(node.children) - 1
            if number_to_op_code(n) != items[0]:
                raise RuntimeError(f'not the expected pattern')
            items.pop(0)
            if items[0] not in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                raise RuntimeError(f'not the expected pattern')
            if items[0] == OP_CHECKMULTISIGVERIFY:
                node.modifiers = 'v'
            items.pop(0)
        elif len(items) > 1 and items[1] == OP_CHECKSEQUENCEVERIFY:
            num = items.pop(0)
            items.pop(0)
            node = cls('older', parent, None)
            cls(str(decode_minimal_num(num)), node, None)
        elif len(items) > 1 and items[1] == OP_CHECKLOCKTIMEVERIFY:
            num = items.pop(0)
            items.pop(0)
            node = cls('after', parent, None)
            cls(str(decode_minimal_num(num)), node, None)
        elif items[0] == OP_1:
            items.pop(0)
            node = cls('just_1', parent, None)
        elif items[0] == OP_0:
            items.pop(0)
            node = cls('just_0', parent, None)
        elif len(items[0]) == 33:
            sec = items.pop(0)
            word = 'pk_k'
            modifiers = None
            if items[0] in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
                op = items.pop(0)
                word = 'pk'
                if op == OP_CHECKSIGVERIFY:
                    modifiers = 'v'
            node = cls(word, parent, modifiers)
            cls(sec.hex(), node, None)
        elif len(items) > 4 and items[0] == OP_DUP \
             and items[1] == OP_HASH160 \
             and len(items[2]) == 20 \
             and items[3] == OP_EQUALVERIFY:
            h160 = items[2]
            for _ in range(4):
                items.pop(0)
            modifiers = None
            word = 'pk_h'
            if items and items[0] in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
                word = 'pkh'
                if items[0] == OP_CHECKSIGVERIFY:
                    modifiers = 'v'
                items.pop(0)
            node = cls(word, parent, modifiers)
            cls(h160.hex(), node, None)
        elif len(items) > 5 and items[0] == OP_SIZE \
             and decode_num(items[1]) == 32 \
             and items[2] == OP_EQUALVERIFY \
             and items[3] in (OP_SHA256, OP_RIPEMD160, OP_HASH160, OP_HASH256) \
             and len(items[4]) in (20, 32) \
             and items[5] in (OP_EQUAL, OP_EQUALVERIFY):
            if items[3] == OP_SHA256:
                word = 'sha256'
            elif items[3] == OP_RIPEMD160:
                word = 'ripemd160'
            elif items[3] == OP_HASH160:
                word = 'hash160'
            else:
                word = 'hash256'
            if items[5] == OP_EQUALVERIFY:
                modifiers = 'v'
            else:
                modifiers = None
            hash_value = items[4]
            for _ in range(6):
                items.pop(0)
            node = cls(word, parent, modifiers)
            cls(hash_value.hex(), node, None)
        elif items[0] == OP_IF:
            items.pop(0)
            child_1 = cls.from_script(items)
            if items[0] != OP_ELSE:
                raise RuntimeError('not the expected pattern')
            items.pop(0)
            child_2 = cls.from_script(items)
            if items[0] != OP_ENDIF:
                raise RuntimeError(f'not the expected pattern {items}')
            items.pop(0)
            if child_1.word == 'just_0':
                node = child_2
                node.modifiers = 'l' + node.modifiers
            elif child_2.word == 'just_0':
                node = child_1
                node.modifiers = 'u' + node.modifiers
            else:
                node = cls('or_i', parent, None, [child_1, child_2])
        elif items[0] == OP_TOALTSTACK:
            items.pop(0)
            node = cls.from_script(items, parent)
            if items[0] != OP_FROMALTSTACK:
                raise RuntimeError('not the expected pattern')
            items.pop(0)
            node.modifiers = 'a' + node.modifiers
        elif items[0] == OP_SWAP:
            items.pop(0)
            node = cls.from_script(items)
            node.modifiers = 's' + node.modifiers
        elif len(items) > 2 and items[0] == OP_DUP and items[1] == OP_IF:
            items.pop(0)
            items.pop(0)
            node = cls.from_script(items, parent)
            if items[0] != OP_ENDIF:
                raise RuntimeError('not the expected pattern')
            items.pop(0)
            node.modifiers = 'd' + node.modifiers
        elif len(items) > 3 and items[0] == OP_SIZE and \
             items[1] == OP_0NOTEQUAL and items[2] == OP_IF:
            for _ in range(3):
                items.pop(0)
            node = cls.from_script(items, parent)
            if items[0] != OP_ENDIF:
                raise RuntimeError('not the expected pattern')
            items.pop(0)
            node.modifiers = 'j' + node.modifiers
        else:
            raise RuntimeError(f'script is not a miniscript {items}')
        while len(items) < last_length:
            if not items:
                return node
            last_length = len(items)
            if items[0] == OP_CHECKSIG:
                node.modifiers = 'c' + node.modifiers
                items.pop(0)
            elif items[0] == OP_CHECKSIGVERIFY:
                node.modifiers = 'vc' + node.modifiers
                items.pop(0)
            elif items[0] == OP_VERIFY:
                node.modifiers = 'v' + node.modifiers
                items.pop(0)
            elif items[0] == OP_0NOTEQUAL:
                node.modifiers = 'n' + node.modifiers
                items.pop(0)
            elif items[0] == OP_NOTIF:
                items.pop(0)
                child = cls.from_script(items)
                if items[0] == OP_ELSE:
                    # andor
                    items.pop(0)
                    child_2 = cls.from_script(items)
                    if items[0] != OP_ENDIF:
                        raise RuntimeError('not the expected pattern')
                    items.pop(0)
                    if child.word == 'just_0':
                        node = cls('and_n', parent, None, [node, child_2])
                    else:
                        node = cls('andor', parent, None,
                                   [node, child_2, child])
                elif items[0] == OP_ENDIF:
                    items.pop(0)
                    # or_c
                    node = cls('or_c', parent, None, [node, child])
                else:
                    raise RuntimeError('not the expected pattern')
            elif len(items) > 1 and items[0] == OP_IFDUP \
                 and items[1] == OP_NOTIF:
                items.pop(0)
                items.pop(0)
                child = cls.from_script(items)
                if items[0] != OP_ENDIF:
                    raise RuntimeError('not the expected pattern')
                items.pop(0)
                node = cls('or_d', parent, None, [node, child])
            elif items[0] == OP_1:
                items.pop(0)
                node.modifiers = 't' + node.modifiers
            else:
                # attempt to look ahead
                try:
                    items_copy = Script(items[:])
                    node2 = cls.from_script(items_copy)
                except RuntimeError as e:
                    continue
                if items_copy and items_copy[0] == OP_BOOLOR:
                    # or_b
                    for _ in range(len(items) - len(items_copy) + 1):
                        items.pop(0)
                    node = cls('or_b', parent, None, [node, node2])
                elif items_copy and items_copy[0] == OP_BOOLAND:
                    # and_b
                    for _ in range(len(items) - len(items_copy) + 1):
                        items.pop(0)
                    node = cls('and_b', parent, None, [node, node2])
                elif items_copy and items_copy[0] == OP_ADD:
                    # thresh
                    for _ in range(len(items) - len(items_copy) + 1):
                        items.pop(0)
                    node = cls('thresh', parent, None, [node, node2])
                    while True:
                        if is_number_op_code(items[0]) \
                           and items[1] in (OP_EQUAL, OP_EQUALVERIFY):
                            break
                        cls.from_script(items, node)
                        if items[0] != OP_ADD:
                            raise RuntimeError('not the expected pattern')
                        items.pop(0)
                    k = op_code_to_number(items.pop(0))
                    first_child = cls(str(k), node, None)
                    node.children.pop()
                    node.children.insert(0, first_child)
                    if items[0] == OP_EQUALVERIFY:
                        node.modifiers = 'v' + node.modifiers
                    items.pop(0)
                else:
                    # and_v
                    for _ in range(len(items) - len(items_copy)):
                        items.pop(0)
                    node = cls('and_v', parent, None, [node, node2])
        return node

    @classmethod
    def tokenize(cls, s):
        c = s.read(1)
        current_token = ''
        tokens = []
        while c:
            if c in ('(', ')', ',', ':'):
                if current_token:
                    tokens.extend([current_token, c])
                    current_token = ''
                else:
                    tokens.append(c)
            else:
                current_token += c
            c = s.read(1)
        if current_token:
            tokens.append(current_token)
        return tokens

    @classmethod
    def parse(cls, s):
        tokens = cls.tokenize(s)
        word, modifiers, parent = None, None, None
        for token in tokens:
            if token == '(':
                parent = cls(word, parent, modifiers)
                word, modifiers = None, None
            elif token in (',', ')'):
                if word:
                    cls(word, parent, modifiers)
                    word, modifiers = None, None
                if token == ')' and parent.parent:
                    parent = parent.parent
            elif token == ':':
                modifiers = word
                word = None
            else:
                word = token
        return parent

    def script(self):
        if self.word == 'pk':
            script = Script(
                [bytes.fromhex(self.children[0].word), OP_CHECKSIG])
        elif self.word == 'pk_k':
            script = Script([bytes.fromhex(self.children[0].word)])
        elif self.word == 'pkh':
            h160 = bytes.fromhex(self.children[0].word)
            script = Script(
                [OP_DUP, OP_HASH160, h160, OP_EQUALVERIFY, OP_CHECKSIG])
        elif self.word == 'pk_h':
            h160 = bytes.fromhex(self.children[0].word)
            script = Script([OP_DUP, OP_HASH160, h160, OP_EQUALVERIFY])
        elif self.word == 'older':
            script = Script([
                encode_minimal_num(int(self.children[0].word)),
                OP_CHECKSEQUENCEVERIFY
            ])
        elif self.word == 'after':
            script = Script([
                encode_minimal_num(int(self.children[0].word)),
                OP_CHECKLOCKTIMEVERIFY
            ])
        elif self.word in ('sha256', 'ripemd160', 'hash256', 'hash160'):
            if self.word == 'sha256':
                op = OP_SHA256
            elif self.word == 'ripemd160':
                op = OP_RIPEMD160
            elif self.word == 'hash256':
                op = OP_HASH256
            else:
                op = OP_HASH160
            script = Script([
                OP_SIZE,
                encode_num(32), OP_EQUALVERIFY, op,
                bytes.fromhex(self.children[0].word), OP_EQUAL
            ])
        elif self.word == 'just_1':
            script = Script([OP_1])
        elif self.word == 'just_0':
            script = Script([OP_0])
        elif self.word == 'and_v':
            script = self.children[0].script() + self.children[1].script()
        elif self.word == 'and_b':
            script = self.children[0].script() + self.children[1].script(
            ) + Script([OP_BOOLAND])
        elif self.word == 'and_n':
            script = self.children[0].script() + Script([
                OP_NOTIF, OP_0, OP_ELSE
            ]) + self.children[1].script() + Script([OP_ENDIF])
        elif self.word == 'or_b':
            script = self.children[0].script() + self.children[1].script(
            ) + Script([OP_BOOLOR])
        elif self.word == 'or_d':
            script = self.children[0].script() + Script([
                OP_IFDUP, OP_NOTIF
            ]) + self.children[1].script() + Script([OP_ENDIF])
        elif self.word == 'or_c':
            script = self.children[0].script() + Script(
                [OP_NOTIF]) + self.children[1].script() + Script([OP_ENDIF])
        elif self.word == 'or_i':
            script = Script([OP_IF]) + self.children[0].script() + Script(
                [OP_ELSE]) + self.children[1].script() + Script([OP_ENDIF])
        elif self.word == 'andor':
            script = self.children[0].script() + Script(
                [OP_NOTIF]) + self.children[2].script() + Script(
                    [OP_ELSE]) + self.children[1].script() + Script([OP_ENDIF])
        elif self.word == 'multi':
            keys = [bytes.fromhex(c.word) for c in self.children[1:]]
            script = Script([
                encode_minimal_num(int(self.children[0].word)), *keys,
                encode_minimal_num(len(keys)), OP_CHECKMULTISIG
            ])
        elif self.word == 'thresh':
            result = self.children[1].script()
            for sub in self.children[2:]:
                result += sub.script() + Script([OP_ADD])
            script = result + Script(
                [encode_minimal_num(int(self.children[0].word)), OP_EQUAL])
        else:
            raise RuntimeError(f'unknown word: {self.word}')
        if self.modifiers:
            for c in reversed(self.modifiers):
                if c == 'a':
                    script = Script([OP_TOALTSTACK]) + script + Script(
                        [OP_FROMALTSTACK])
                elif c == 's':
                    script = Script([OP_SWAP]) + script
                elif c == 'c':
                    script += Script([OP_CHECKSIG])
                elif c == 'd':
                    script = Script([OP_DUP, OP_IF]) + script + Script(
                        [OP_ENDIF])
                elif c == 'v':
                    if script[-1] == OP_EQUAL:
                        script[-1] = OP_EQUALVERIFY
                    elif script[-1] == OP_CHECKSIG:
                        script[-1] = OP_CHECKSIGVERIFY
                    elif script[-1] == OP_CHECKMULTISIG:
                        script[-1] = OP_CHECKMULTISIGVERIFY
                    else:
                        script += Script([OP_VERIFY])
                elif c == 'j':
                    script = Script([OP_SIZE, OP_0NOTEQUAL, OP_IF
                                     ]) + script + Script([OP_ENDIF])
                elif c == 'n':
                    script += Script([OP_0NOTEQUAL])
                elif c == 't':
                    script += Script([OP_1])
                elif c == 'u':
                    script = Script([OP_IF]) + script + Script(
                        [OP_ELSE, OP_0, OP_ENDIF])
                elif c == 'l':
                    script = Script([OP_IF, OP_0, OP_ELSE]) + script + Script(
                        [OP_ENDIF])
        return script

    def validate(self):
        # sanity check
        if self.word in ('sha256', 'hash256'):
            if len(bytes.fromhex(self.children[0].word)) != 32:
                raise ValueError(
                    f'Hash length should be 32 bytes {self.children[0].word}')
        elif self.word in ('ripemd160', 'hash160'):
            if len(bytes.fromhex(self.children[0].word)) != 20:
                raise ValueError('Hash length should be 20 bytes')
        elif self.word in ('older', 'after'):
            k = int(self.children[0].word)
            if k < 1 or k >= 0x80000000:
                raise ValueError(
                    f'Timelocks need a number between 1 and 0x80000000: {k}')
        elif self.word in ('thresh', 'multi'):
            k = int(self.children[0].word)
            if k > len(self.children) - 1:
                raise ValueError(
                    f'{self.word} should have at least {k} subexpressions but has {len(self.children) - 1}'
                )
        elif self.word in ('and_v', 'and_b', 'and_n', 'or_b', 'or_c', 'or_d',
                           'or_i'):
            if len(self.children) != 2:
                raise ValueError(
                    f'{self.word} should have 2 subexpressions, not {len(self.children)}'
                )
        elif self.word == 'andor':
            if len(self.children) != 3:
                raise ValueError(
                    f'andor should have 3 subexpressions, not {len(self.children)}'
                )
        elif self.word in ('pk', 'pk_k', 'pkh', 'pk_h'):
            if len(self.children) != 1:
                raise ValueError(f'{self.word} should have 1 subexpression')
        else:
            if len(self.children) != 0:
                raise ValueError(f'{self.word} should have no subexpressions')

    def compute_type(self):
        self.validate()
        if self.word == 'pk_k':
            self.type = ExpressionType('Konudemsx')
            self.size = 34
        elif self.word == 'pk_h':
            self.type = ExpressionType('Knudemsx')
            self.size = 24
        elif self.word == 'pk':
            self.type = ExpressionType('Bdemnosu')
            self.size = 35
        elif self.word == 'pkh':
            self.type = ExpressionType('Bdemnsu')
            self.size = 25
        elif self.word in ('older', 'after'):
            self.type = ExpressionType('Bzfmx')
            script_num = encode_minimal_num(int(self.children[0].word))
            self.size = len(Script([script_num]).raw_serialize()) + 1
        elif self.word in ('sha256', 'hash256'):
            self.type = ExpressionType('Bonudm')
            self.size = 6 + 33
        elif self.word in ('ripemd160', 'hash160'):
            self.type = ExpressionType('Bonudm')
            self.size = 6 + 21
        elif self.word == 'just_1':
            self.type = ExpressionType('Bzufmx')
            self.size = 1
        elif self.word == 'just_0':
            self.type = ExpressionType('Bzudemsx')
            self.size = 1
        elif self.word == 'multi':
            self.type = ExpressionType('Bnudems')
            self.size = 3 + 34 * (len(self.children) - 1)
        elif self.word == 'and_v':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                ('', 'B')['V' in x and 'B' in y]  # B=V_x*B_y
                + ('', 'V')['V' in x and 'V' in y]  # V=V_x*V_y
                + ('', 'K')['V' in x and 'K' in y]  # K=V_x*K_y
                +
                ('', 'n')['n' in x or ('z' in x and 'n' in y)]  # n=n_x+z_x*n_y
                + ('', 'o')[('z' in x and 'o' in y) or
                            ('o' in x and 'z' in y)]  # o=o_x*z_y+z_x*o_y
                + ('', 'd')['d' in x and 'd' in y]  # d=d_x*d_y
                + ('', 'm')['m' in x and 'm' in y]  # m=m_x*m_y
                + ('', 'z')['z' in x and 'z' in y]  # z=z_x*z_y
                + ('', 's')['s' in x or 's' in y]  # s=s_x+s_y
                + ('', 'f')['s' in x or 'f' in y]  # f=f_y+s_x
                + ('', 'u')['u' in y]  # u=u_y
                + ('', 'x')['x' in y]  # x=x_y
            )
            self.size = self.children[0].size + \
                self.children[1].size
        elif self.word == 'and_b':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                'ux' + ('', 'B')['W' in y and 'B' in x]  # B=B_x*W_y
                +
                ('', 'n')['n' in x or ('z' in x and 'n' in y)]  # n=n_x+z_x*n_y
                + ('', 'o')[('z' in x and 'o' in y) or
                            ('o' in x and 'z' in y)]  # o=o_x*z_y+z_x*o_y
                + ('', 'd')['d' in x and 'd' in y]  # d=d_x*d_y
                + ('', 'm')['m' in x and 'm' in y]  # m=m_x*m_y
                + ('', 'z')['z' in x and 'z' in y]  # z=z_x*z_y
                + ('', 's')['s' in x or 's' in y]  # s=s_x+s_y
                + ('', 'e')['es' in x and 'es' in y]  # e=e_x*e_y*s_x*s_y
                + ('', 'f')[('f' in x and 'f' in y) or 'fs' in x
                            or 'fs' in y]  # f=f_x*f_y + f_x*s_x + f_y*s_y
            )
            self.size = self.children[0].size + \
                self.children[1].size + 1
        elif self.word == 'and_n':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                'x' + ('', 'B')['Bdu' in x and 'B' in y]  # B=B_x*d_x*u_x*B_y
                + ('', 'z')['z' in x and 'z' in y]  # z=z_x*z_y
                + ('', 'o')['o' in x and 'z' in y]  # o=o_x*z_y
                + ('', 'u')['u' in y]  # u=u_y
                + ('', 'd')['d' in x]  # d=d_x
                + ('', 's')['s' in x or 's' in y]  # s=s_x+s_y
                + ('',
                   'e')['e' in x and ('s' in x or 's' in y)]  # e=e_x*(s_x+s_y)
                + ('', 'm')['em' in x and 'm' in y]  # m=m_x*m_y*e_x
            )
            self.size = self.children[0].size + \
                self.children[1].size + 4
        elif self.word == 'or_b':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                'dux' + ('', 'B')['Bd' in x and 'Wd' in y]  # B=B_x*d_x*W_x*d_y
                + ('', 'o')[('z' in x and 'o' in y) or
                            ('o' in x and 'z' in y)]  # o=o_x*z_y+z_x*o_y
                + ('', 'm')['em' in x and 'em' in y and (
                    's' in x or 's' in y)]  # m=m_x*m_y*e_x*e_y*(s_x+s_y)
                + ('', 'z')['z' in x and 'z' in y]  # z=z_x*z_y
                + ('', 's')['s' in x and 's' in y]  # s=s_x*s_y
                + ('', 'e')['e' in x and 'e' in y]  # e=e_x*e_y
            )
            self.size = self.children[0].size + \
                self.children[1].size + 1
        elif self.word == 'or_c':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                'fx' + ('', 'V')['Bud' in x and 'V' in y]  # V=V_y*B_x*u_x*d_x
                + ('', 'o')['o' in x and 'z' in y]  # o=o_x*z_y
                + ('', 'm')['me' in x and 'm' in y and
                            ('s' in x or 's' in y)]  # m=m_x*m_y*e_x*(s_x+s_y)
                + ('', 'z')['z' in x and 'z' in y]  # z=z_x*z_y
                + ('', 's')['s' in x and 's' in y]  # s=s_x*s_y
            )
            self.size = self.children[0].size + \
                self.children[1].size + 2
        elif self.word == 'or_d':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                'x' + ('', 'B')['Bdu' in x and 'B' in y]  # B=B_y*B_x*d_x*u_x
                + ('', 'o')['o' in x and 'z' in y]  # o=o_x*z_y
                + ('', 'm')['me' in x and 'm' in y and
                            ('s' in x or 's' in y)]  # m=m_x*m_y*e_x*(s_x+s_y)
                + ('', 'z')['z' in x and 'z' in y]  # z=z_x*z_y
                + ('', 's')['s' in x and 's' in y]  # s=s_x*s_y
                + ('', 'e')['e' in x and 'e' in y]  # e=e_x*e_y
                + ('', 'u')['u' in y]  # u=u_y
                + ('', 'd')['d' in y]  # d=d_y
                + ('', 'f')['f' in y]  # f=f_y
            )
            self.size = self.children[0].size + \
                self.children[1].size + 3
        elif self.word == 'or_i':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                'x' + ('', 'V')['V' in x and 'V' in y]  # V=V_x*V_y
                + ('', 'B')['B' in x and 'B' in y]  # B=B_x*B_y
                + ('', 'K')['K' in x and 'K' in y]  # K=K_x*K_y
                + ('', 'u')['u' in x and 'u' in y]  # u=u_x*u_y
                + ('', 'f')['f' in x and 'f' in y]  # f=f_x*f_y
                + ('', 's')['s' in x and 's' in y]  # s=s_x*s_y
                + ('', 'o')['z' in x and 'z' in y]  # o=z_x*z_y
                + ('', 'e')[('e' in x and 'f' in y) or
                            ('f' in x and 'e' in y)]  # e=e_x*f_y+f_x*e_y
                + ('', 'm')['m' in x and 'm' in y and
                            ('s' in x or 's' in y)]  # m=m_x*m_y*(s_x+s_y)
                + ('', 'd')['d' in x or 'd' in y]  # d=d_x+d_y
            )
            self.size = self.children[0].size + \
                self.children[1].size + 3
        elif self.word == 'andor':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            z = self.children[2].compute_type()
            self.type = ExpressionType(
                'x' + ('', 'B')['Bdu' in x and 'B' in y
                                and 'B' in z]  # B=B_x*d_x*u_x*B_y*B_z
                + ('', 'K')['Bdu' in x and 'K' in y
                            and 'K' in z]  # K=B_x*d_x*u_x*K_y*K_z
                + ('', 'V')['Bdu' in x and 'V' in y
                            and 'V' in z]  # V=B_x*d_x*u_x*V_y*V_z
                +
                ('', 'z')['z' in x and 'z' in y and 'z' in z]  # z=z_x*z_y*z_z
                + ('', 'o')[('z' in x and 'o' in y and 'o' in z) or
                            ('o' in x and 'z' in y and 'z' in z
                             )]  # o=o_x*z_y*z_z+z_x*o_y*o_z
                + ('', 'u')['u' in y and 'u' in z]  # u=u_y*u_z
                + ('',
                   'f')[('s' in x or 'f' in y) and 'f' in z]  # f=(s_x+f_y)*f_z
                + ('', 'd')['d' in z]  # d=d_z
                + ('', 'e')[('s' in x or 'f' in y) and 'e' in x
                            and 'e' in z]  # e=e_x*e_z*(s_x+s_y)
                + ('', 'm')['em' in x and 'm' in y and 'm' in z and
                            ('s' in x or 's' in y or 's' in z
                             )]  # m=m_x*m_y*m_z*e_x*(s_x+s_y+s_z)
                + ('',
                   's')['s' in z and ('s' in x or 's' in y)]  # s=s_z*(s_x+s_y)
            )
            self.size = self.children[0].size + \
                self.children[1].size + \
                self.children[2].size + 3
        elif self.word == 'thresh':
            all_e, all_m, num_s, args = True, True, 0, 0
            k = int(self.children[0].word)
            for i, child in enumerate(self.children[1:]):
                t = child.compute_type()
                if i == 0 and 'Bdu' not in t:
                    raise ValueError(
                        'First expression in thresh should be Bdu')
                elif i > 0 and 'Wdu' not in t:
                    raise ValueError(
                        f'non-first expression in thresh should be Wdu {t} {child}'
                    )
                if 'e' not in t:
                    all_e = False
                if 'm' not in t:
                    all_m = False
                if 's' in t:
                    num_s += 1
                if 'o' in t:
                    args += 1
                elif 'z' not in t:
                    args += 2
            self.type = ExpressionType(
                'Bdu' + ('', 'z')[args == 0]  # all z's to get z
                + ('', 'o')[args == 1]  # one o, all z's to get o
                + ('', 'e')[all_e and num_s == len(self.children) -
                            1]  # all s's and all e's
                + ('', 'm')[all_e and all_m and num_s >= len(self.children) -
                            1 - k]  # all e's and all e's
                + ('', 's')[num_s >= len(self.children) - k])
            self.size = len(encode_minimal_num(int(self.children[0].word)))
            for child in self.children[1:]:
                self.size += child.size + 1
        else:
            raise SyntaxError(f'bad word {self.word}')
        assert self.type, f'{self.word} has no type'
        # take care of modifiers
        for m in reversed(self.modifiers):
            if m == 'a':
                self.type = ExpressionType('x' +
                                           ('', 'W')['B' in self.type]  # W=B_x
                                           +
                                           ('', 'u')['u' in self.type]  # u=u_x
                                           +
                                           ('', 'd')['d' in self.type]  # d=d_x
                                           +
                                           ('', 'f')['f' in self.type]  # f=f_x
                                           +
                                           ('', 'e')['e' in self.type]  # e=e_x
                                           +
                                           ('', 'm')['m' in self.type]  # m=m_x
                                           +
                                           ('', 's')['s' in self.type]  # s=s_x
                                           )
                self.size += 2
            elif m == 's':
                self.type = ExpressionType(
                    ('', 'W')['Bo' in self.type]  # W=B_x*o_x
                    + ('', 'u')['u' in self.type]  # u=u_x
                    + ('', 'd')['d' in self.type]  # d=d_x
                    + ('', 'f')['f' in self.type]  # f=f_x
                    + ('', 'e')['e' in self.type]  # e=e_x
                    + ('', 'm')['m' in self.type]  # m=m_x
                    + ('', 's')['s' in self.type]  # s=s_x
                    + ('', 'x')['x' in self.type]  # x=x_x
                )
                self.size += 1
            elif m == 'c':
                self.type = ExpressionType(
                    # (a, b)[expr] will eval to a if false b if true
                    'us' + ('', 'B')['K' in self.type]  # B=K_x
                    + ('', 'o')['o' in self.type]  # o=o_x
                    + ('', 'n')['n' in self.type]  # n=n_x
                    + ('', 'd')['d' in self.type]  # d=d_x
                    + ('', 'f')['f' in self.type]  # f=f_x
                    + ('', 'e')['e' in self.type]  # e=e_x
                    + ('', 'm')['m' in self.type]  # m=m_x
                    + 'us')
                self.size += 1
            elif m == 'd':
                self.type = ExpressionType(
                    'nudx' + ('', 'B')['Vz' in self.type]  # B=V_x*z_x
                    + ('', 'o')['z' in self.type]  # o=z_x
                    + ('', 'e')['f' in self.type]  # e=f_x
                    + ('', 'm')['m' in self.type]  # m=m_x
                    + ('', 's')['s' in self.type]  # s=s_x
                )
                self.size += 3
            elif m == 'v':
                if 'x' in self.type:
                    self.size += 1
                self.type = ExpressionType(
                    # (a, b)[expr] will eval to a if false b if true
                    'fx' + ('', 'V')['B' in self.type]  # V=B_x
                    + ('', 'z')['z' in self.type]  # z=z_x
                    + ('', 'o')['o' in self.type]  # o=o_x
                    + ('', 'n')['n' in self.type]  # n=n_x
                    + ('', 'm')['m' in self.type]  # m=m_x
                    + ('', 's')['s' in self.type]  # s=s_x
                )
            elif m == 'j':
                self.type = ExpressionType(
                    'ndx' + ('', 'B')['Bn' in self.type]  # B=B_x*n_x
                    + ('', 'e')['f' in self.type]  # e=f_x
                    + ('', 'o')['o' in self.type]  # o=o_x
                    + ('', 'u')['u' in self.type]  # u=u_x
                    + ('', 'm')['m' in self.type]  # m=m_x
                    + ('', 's')['s' in self.type]  # s=s_x
                )
                self.size += 4
            elif m == 'n':
                self.type = ExpressionType(
                    'ux' + ('', 'B')['B' in self.type]  # B=B_x
                    + ('', 'z')['z' in self.type]  # z=z_x
                    + ('', 'o')['o' in self.type]  # o=o_x
                    + ('', 'n')['n' in self.type]  # n=n_x
                    + ('', 'd')['d' in self.type]  # d=d_x
                    + ('', 'f')['f' in self.type]  # f=f_x
                    + ('', 'e')['e' in self.type]  # e=e_x
                    + ('', 'm')['m' in self.type]  # m=m_x
                    + ('', 's')['s' in self.type]  # s=s_x
                )
                self.size += 1
            elif m in ('l', 'u'):
                self.type = ExpressionType(
                    # (a, b)[expr] will eval to a if false b if true
                    'dx' + ('', 'B')['B' in self.type]  # B=B_x
                    + ('', 'u')['u' in self.type]  # u=u_x
                    + ('', 'm')['m' in self.type]  # m=m_x
                    + ('', 's')['s' in self.type]  # s=s_x
                    + ('', 'o')['z' in self.type]  # o=z_x
                    + ('', 'e')['f' in self.type]  # e=f_x
                )
                self.size += 4
            elif m == 't':
                self.type = ExpressionType(
                    # (a, b)[expr] will eval to a if false b if true
                    'fux' + ('', 'B')['V' in self.type]  # B=V_x
                    + ('', 'z')['z' in self.type]  # z=z_x
                    + ('', 'o')['o' in self.type]  # o=o_x
                    + ('', 'd')['d' in self.type]  # d=d_x
                    + ('', 'm')['m' in self.type]  # m=m_x
                    + ('', 's')['s' in self.type]  # s=s_x
                )
                self.size += 1
        return self.type


EXPRESSION_TYPE_ALPHABET = 'BVKWzonduefsmx'


class ExpressionType(int):
    def __new__(cls, s):
        result = 0
        for letter in s:
            if letter not in EXPRESSION_TYPE_ALPHABET:
                raise KeyError('Not a valid type')
            result |= (1 << EXPRESSION_TYPE_ALPHABET.index(letter))
        e = super().__new__(cls, result)
        if 'z' in e and 'o' in e:
            raise TypeError('Cannot consume both 1 and 0 arguments')
        if 'n' in e and 'z' in e:
            raise TypeError(
                'Cannot consume both 0 elements and 1 or more elements')
        if 'V' in e and 'd' in e:
            raise TypeError(
                'Verifying expressions halt and are not dissatisfiable')
        if 'K' in e and 'u' not in e:
            raise TypeError('Key expressions are also unit expressions')
        if 'V' in e and 'u' in e:
            raise TypeError(
                'Verifying expressions do not push anything back so are not unit expressions'
            )
        if 'e' in e and 'f' in e:
            raise TypeError(
                'Dissatisfactions cannot both be non-malleable and also have at least one signature'
            )
        if 'e' in e and 'd' not in e:
            raise TypeError(
                'Non-malleable Dissatisfactions imply dissatisfiability')
        if 'V' in e and 'e' in e:
            raise TypeError('Verifying expressions are not dissatisfiable')
        if 'd' in e and 'f' in e:
            raise TypeError('Dissatisfiability implies no signature is needed')
        if 'V' in e and 'f' not in e:
            raise TypeError(
                'Verifying expressions have no dissatisfactions, meaning it is forced'
            )
        if 'K' in e and 's' not in e:
            raise TypeError('Key expressions always require a signature')
        if 'z' in e and 'm' not in e:
            raise TypeError(
                'Zero arguments being consumed imply non-malleability')
        return e

    def __repr__(self):
        result = ''
        for i, letter in enumerate(EXPRESSION_TYPE_ALPHABET):
            if self & (1 << i):
                result += letter
        return result

    def __contains__(self, letters):
        result = True
        for letter in letters:
            index = EXPRESSION_TYPE_ALPHABET.index(letter)
            result = result and bool(self & (1 << index))
        return result
