from io import StringIO
from unittest import TestCase, skip

from expression import BetterBool, ExpressionType
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
                raise SyntaxError(f'not the expected pattern')
            items.pop(0)
            if items[0] not in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                raise SyntaxError(f'not the expected pattern')
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
                raise SyntaxError('not the expected pattern')
            items.pop(0)
            child_2 = cls.from_script(items)
            if items[0] != OP_ENDIF:
                raise SyntaxError(f'not the expected pattern {items}')
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
                raise SyntaxError('not the expected pattern')
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
                raise SyntaxError('not the expected pattern')
            items.pop(0)
            node.modifiers = 'd' + node.modifiers
        elif len(items) > 3 and items[0] == OP_SIZE and \
             items[1] == OP_0NOTEQUAL and items[2] == OP_IF:
            for _ in range(3):
                items.pop(0)
            node = cls.from_script(items, parent)
            if items[0] != OP_ENDIF:
                raise SyntaxError('not the expected pattern')
            items.pop(0)
            node.modifiers = 'j' + node.modifiers
        else:
            raise SyntaxError(f'script is not a miniscript {items}')
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
                        raise SyntaxError('not the expected pattern')
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
                    raise SyntaxError('not the expected pattern')
            elif len(items) > 1 and items[0] == OP_IFDUP \
                 and items[1] == OP_NOTIF:
                items.pop(0)
                items.pop(0)
                child = cls.from_script(items)
                if items[0] != OP_ENDIF:
                    raise SyntaxError('not the expected pattern')
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
                except SyntaxError as e:
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
                            raise SyntaxError('not the expected pattern')
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
            sec = bytes.fromhex(self.children[0].word)
            script = Script([sec, OP_CHECKSIG])
        elif self.word == 'pk_k':
            # sometimes the checksig can sit outside an IF
            # to save a byte, which motivates this script
            # IF <x> ELSE <y> ENDIF CHECKSIG
            sec = bytes.fromhex(self.children[0].word)
            script = Script([sec])
        elif self.word == 'pkh':
            h160 = bytes.fromhex(self.children[0].word)
            script = Script(
                [OP_DUP, OP_HASH160, h160, OP_EQUALVERIFY, OP_CHECKSIG])
        elif self.word == 'pk_h':
            # sometimes the checksig can sit outside an IF
            # to save a byte, which motivates this script
            # IF <x> ELSE <y> ENDIF CHECKSIG
            h160 = bytes.fromhex(self.children[0].word)
            script = Script([OP_DUP, OP_HASH160, h160, OP_EQUALVERIFY])
        elif self.word == 'older':
            amount = encode_minimal_num(int(self.children[0].word))
            script = Script([amount, OP_CHECKSEQUENCEVERIFY])
        elif self.word == 'after':
            amount = encode_minimal_num(int(self.children[0].word))
            script = Script([amount, OP_CHECKLOCKTIMEVERIFY])
        elif self.word in ('sha256', 'ripemd160', 'hash256', 'hash160'):
            # hashlocks
            if self.word == 'sha256':
                op = OP_SHA256
            elif self.word == 'ripemd160':
                op = OP_RIPEMD160
            elif self.word == 'hash256':
                op = OP_HASH256
            else:
                op = OP_HASH160
            h = bytes.fromhex(self.children[0].word)
            script = Script(
                [OP_SIZE,
                 encode_num(32), OP_EQUALVERIFY, op, h, OP_EQUAL])
        elif self.word == 'just_1':
            script = Script([OP_1])
        elif self.word == 'just_0':
            script = Script([OP_0])
        elif self.word == 'and_v':
            # "and" with a V expression and B, V or K
            # outputs whatever the second one is
            x = self.children[0].script()
            y = self.children[1].script()
            script = x + y
        elif self.word == 'and_b':
            # "and" with a B expression and a W expression
            # outputs a B
            x = self.children[0].script()
            y = self.children[1].script()
            script = x + y + [OP_BOOLAND]
        elif self.word == 'and_n':
            # "and" with two B expressions, the first being du
            # outputs a B
            x = self.children[0].script()
            y = self.children[1].script()
            script = x + [OP_NOTIF, OP_0, OP_ELSE] + y + [OP_ENDIF]
        elif self.word == 'or_b':
            # "or" with a B expression and a W expression, both being d
            # outputs a B
            x = self.children[0].script()
            y = self.children[1].script()
            script = x + y + [OP_BOOLOR]
        elif self.word == 'or_c':
            # "or" with a B expression and a V expression, first being du
            # outputs a V
            x = self.children[0].script()
            y = self.children[1].script()
            script = x + [OP_NOTIF] + y + [OP_ENDIF]
        elif self.word == 'or_d':
            # "or" with two B expressions, first being du
            # outputs a B
            x = self.children[0].script()
            y = self.children[1].script()
            script = x + [OP_IFDUP, OP_NOTIF] + y + [OP_ENDIF]
        elif self.word == 'or_i':
            # "or" with two B, V or K expressions
            # outputs whatever the two expressions are
            x = self.children[0].script()
            y = self.children[1].script()
            script = [OP_IF] + x + [OP_ELSE] + y + [OP_ENDIF]
        elif self.word == 'andor':
            #
            x = self.children[0].script()
            y = self.children[1].script()
            z = self.children[2].script()
            script = x + [OP_NOTIF] + z + [OP_ELSE] + y + [OP_ENDIF]
        elif self.word == 'multi':
            # for multisig
            keys = [bytes.fromhex(c.word) for c in self.children[1:]]
            k = encode_minimal_num(int(self.children[0].word))
            n = encode_minimal_num(len(keys))
            script = Script([k, *keys, n, OP_CHECKMULTISIG])
        elif self.word == 'thresh':
            # useful meta condition, first has to be Bdu, rest Wdu
            script = self.children[1].script()
            for sub in self.children[2:]:
                script += sub.script() + [OP_ADD]
            k = encode_minimal_num(int(self.children[0].word))
            script += [k, OP_EQUAL]
        else:
            raise SyntaxError(f'unknown word: {self.word}')
        if self.modifiers:
            for c in reversed(self.modifiers):
                if c == 'a':
                    # Turn B into W
                    script = [OP_TOALTSTACK] + script + [OP_FROMALTSTACK]
                elif c == 's':
                    # Turn Bo into W
                    script = [OP_SWAP] + script
                elif c == 'c':
                    # Turn K into B
                    script += [OP_CHECKSIG]
                elif c == 'd':
                    # Turn Vz into B
                    script = [OP_DUP, OP_IF] + script + [OP_ENDIF]
                elif c == 'v':
                    # Turn B into V
                    if script[-1] == OP_EQUAL:
                        script[-1] = OP_EQUALVERIFY
                    elif script[-1] == OP_CHECKSIG:
                        script[-1] = OP_CHECKSIGVERIFY
                    elif script[-1] == OP_CHECKMULTISIG:
                        script[-1] = OP_CHECKMULTISIGVERIFY
                    else:
                        script += [OP_VERIFY]
                elif c == 'j':
                    # bypass if the top stack element is 0
                    script = [OP_SIZE, OP_0NOTEQUAL, OP_IF] \
                        + script + [OP_ENDIF]
                elif c == 'n':
                    # turn B into a Bu (for feeding into IF)
                    script += [OP_0NOTEQUAL]
                elif c == 't':
                    # turn V into B
                    script += [OP_1]
                elif c == 'u':
                    # turn z into o (consume one)
                    script = [OP_IF] + script + [OP_ELSE, OP_0, OP_ENDIF]
                elif c == 'l':
                    # turn z into o (consume one)
                    script = [OP_IF, OP_0, OP_ELSE] + script + [OP_ENDIF]
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
                # <x> <y>
                (x.V * y.B).B  # B=V_x*B_y
                + (x.V * y.V).V  # V=V_x*V_y
                + (x.V * y.K).K  # K=V_x*K_y
                + (x.n + x.z * y.n).n  # n=n_x+z_x*n_y
                + (x.z * y.o + x.o * y.z).o  # o=o_x*z_y+z_x*o_y
                + (x.d * y.d).d  # d=d_x*d_y
                + (x.m * y.m).m  # m=m_x*m_y
                + (x.z * y.z).z  # z=z_x*z_y
                + (x.s + y.s).s  # s=s_x+s_y
                + (x.s + y.f).f  # f=f_y+s_x
                + y.u.u  # u=u_y
                + y.x.x  # x=x_y
            )
            self.size = self.children[0].size + \
                self.children[1].size
        elif self.word == 'and_b':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                # <x> <y> BOOLAND
                'ux' + (y.W * x.B).B  # B=B_x*W_y
                + (x.n + x.z * y.n).n  # n=n_x+z_x*n_y
                + (x.z * y.o + x.o * y.z).o  # o=o_x*z_y+z_x*o_y
                + (x.d * y.d).d  # d=d_x*d_y
                + (x.m * y.m).m  # m=m_x*m_y
                + (x.z * y.z).z  # z=z_x*z_y
                + (x.s + y.s).s  # s=s_x+s_y
                + (x.es * y.es).e  # e=e_x*e_y*s_x*s_y
                + (x.f * y.f + x.fs + y.fs).f  # f=f_x*f_y + f_x*s_x + f_y*s_y
            )
            self.size = self.children[0].size + \
                self.children[1].size + 1
        elif self.word == 'and_n':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                # <x> NOTIF 0 ELSE <y> ENDIF
                'x' + (x.Bdu * y.B).B  # B=B_x*d_x*u_x*B_y
                + (x.z * y.z).z  # z=z_x*z_y
                + (x.o * y.z).o  # o=o_x*z_y
                + y.u.u  # u=u_y
                + x.d.d  # d=d_x
                + (x.s + y.s).s  # s=s_x+s_y
                + (x.e * (x.s + y.s)).e  # e=e_x*(s_x+s_y)
                + (x.em * y.m).m  # m=m_x*m_y*e_x
            )
            self.size = self.children[0].size + \
                self.children[1].size + 4
        elif self.word == 'or_b':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                # <x> <y> BOOLOR
                'dux' + (x.Bd * y.Wd).B  # B=B_x*d_x*W_x*d_y
                + (x.z * y.o + x.o * y.z).o  # o=o_x*z_y+z_x*o_y
                + (x.em * y.em * (x.s + y.s)).m  # m=m_x*m_y*e_x*e_y*(s_x+s_y)
                + (x.z * y.z).z  # z=z_x*z_y
                + (x.s * y.s).s  # s=s_x*s_y
                + (x.e * y.e).e  # e=e_x*e_y
            )
            self.size = self.children[0].size + \
                self.children[1].size + 1
        elif self.word == 'or_c':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                # <x> NOTIF <y> ENDIF
                'fx' + (x.Bud * y.V).V  # V=V_y*B_x*u_x*d_x
                + (x.o * y.z).o  # o=o_x*z_y
                + (x.me * y.m * (x.s + y.s)).m  # m=m_x*m_y*e_x*(s_x+s_y)
                + (x.z * y.z).z  # z=z_x*z_y
                + (x.s * y.s).s  # s=s_x*s_y
            )
            self.size = self.children[0].size + \
                self.children[1].size + 2
        elif self.word == 'or_d':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                # <x> IFDUP NOTiF <y> ENDIF
                'x' + (x.Bdu * y.B).B  # B=B_y*B_x*d_x*u_x
                + (x.o * y.z).o  # o=o_x*z_y
                + (x.me * y.m * (x.s + y.s)).m  # m=m_x*m_y*e_x*(s_x+s_y)
                + (x.z * y.z).z  # z=z_x*z_y
                + (x.s * y.s).s  # s=s_x*s_y
                + (x.e * y.e).e  # e=e_x*e_y
                + y.u.u  # u=u_y
                + y.d.d  # d=d_y
                + y.f.f  # f=f_y
            )
            self.size = self.children[0].size + \
                self.children[1].size + 3
        elif self.word == 'or_i':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            self.type = ExpressionType(
                # IF <x> ELSE <y> ENDIF
                'x' + (x.V * y.V).V  # V=V_x*V_y
                + (x.B * y.B).B  # B=B_x*B_y
                + (x.K * y.K).K  # K=K_x*K_y
                + (x.u * y.u).u  # u=u_x*u_y
                + (x.f * y.f).f  # f=f_x*f_y
                + (x.s * y.s).s  # s=s_x*s_y
                + (x.z * y.z).o  # o=z_x*z_y
                + (x.e * y.f + x.f * y.e).e  # e=e_x*f_y+f_x*e_y
                + (x.m * y.m * (x.s + y.s)).m  # m=m_x*m_y*(s_x+s_y)
                + (x.d + y.d).d  # d=d_x+d_y
            )
            self.size = self.children[0].size + \
                self.children[1].size + 3
        elif self.word == 'andor':
            x = self.children[0].compute_type()
            y = self.children[1].compute_type()
            z = self.children[2].compute_type()
            self.type = ExpressionType(
                # <x> NOTIF <z> ELSE <y> ENDIF
                'x' + (x.Bdu * y.B * z.B).B  # B=B_x*d_x*u_x*B_y*B_z
                + (x.Bdu * y.K * z.K).K  # K=B_x*d_x*u_x*K_y*K_z
                + (x.Bdu * y.V * z.V).V  # V=B_x*d_x*u_x*V_y*V_z
                + (x.z * y.z * z.z).z  # z=z_x*z_y*z_z
                + (x.z * y.o * z.o +
                   x.o * y.z * z.z).o  # o=o_x*z_y*z_z+z_x*o_y*o_z
                + (y.u * z.u).u  # u=u_y*u_z
                + ((x.s + y.f) * z.f).f  # f=(s_x+f_y)*f_z
                + z.d.d  # d=d_z
                + ((x.s + y.f) * x.e * z.e).e  # e=e_x*e_z*(s_x+s_y)
                + (x.em * y.m * z.m *
                   (x.s + y.s + z.s)).m  # m=m_x*m_y*m_z*e_x*(s_x+s_y+s_z)
                + (z.s * (x.s + y.s)).s  # s=s_z*(s_x+s_y)
            )
            self.size = self.children[0].size + \
                self.children[1].size + \
                self.children[2].size + 3
        elif self.word == 'thresh':
            all_e, all_m = BetterBool(True), BetterBool(True)
            num_s, args = 0, 0
            k = int(self.children[0].word)
            for i, child in enumerate(self.children[1:]):
                t = child.compute_type()
                if i == 0 and not t.Bdu:
                    raise ValueError(
                        'First expression in thresh should be Bdu')
                elif i > 0 and not t.Wdu:
                    raise ValueError(
                        f'non-first expression in thresh should be Wdu {t} {child}'
                    )
                all_e *= t.e
                all_m *= t.m
                if t.s:
                    num_s += 1
                if t.o:
                    args += 1
                elif not t.z:
                    args += 2
            self.type = ExpressionType(
                'Bdu'
                # all z's to get z
                + BetterBool(args == 0).z
                # one o, all z's to get o
                + BetterBool(args == 1).o
                # all s's and all e's
                + (all_e * (num_s == len(self.children) - 1)).e
                # all e's and all m's and some s's
                + (all_e * all_m * (num_s >= len(self.children) - 1 - k)).m
                # some s's
                + BetterBool(num_s >= len(self.children) - k).s)
            self.size = len(encode_minimal_num(int(self.children[0].word)))
            for child in self.children[1:]:
                self.size += child.size + 1
        else:
            raise SyntaxError(f'bad word {self.word}')
        assert self.type, f'{self.word} has no type'
        # take care of modifiers
        for m in reversed(self.modifiers):
            if m == 'a':
                self.type = ExpressionType(
                    # TOALTSTACK <x> FROMALTSTACK
                    'x' + self.type.B.W  # W=B_x
                    + self.type.u.u  # u=u_x
                    + self.type.d.d  # d=d_x
                    + self.type.f.f  # f=f_x
                    + self.type.e.e  # e=e_x
                    + self.type.m.m  # m=m_x
                    + self.type.s.s  # s=s_x
                )
                self.size += 2
            elif m == 's':
                self.type = ExpressionType(
                    # SWAP <x>
                    (self.type.Bo).W  # W=B_x*o_x
                    + self.type.u.u  # u=u_x
                    + self.type.d.d  # d=d_x
                    + self.type.f.f  # f=f_x
                    + self.type.e.e  # e=e_x
                    + self.type.m.m  # m=m_x
                    + self.type.s.s  # s=s_x
                    + self.type.x.x  # x=x_x
                )
                self.size += 1
            elif m == 'c':
                self.type = ExpressionType(
                    # <x> CHECKSIG
                    'us' + self.type.K.B  # B=K_x
                    + self.type.o.o  # o=o_x
                    + self.type.n.n  # n=n_x
                    + self.type.d.d  # d=d_x
                    + self.type.f.f  # f=f_x
                    + self.type.e.e  # e=e_x
                    + self.type.m.m  # m=m_x
                )
                self.size += 1
            elif m == 'd':
                self.type = ExpressionType(
                    # DUP IF <x> ENDIF
                    'nudx' + (self.type.Vz).B  # B=V_x*z_x
                    + self.type.z.o  # o=z_x
                    + self.type.f.e  # e=f_x
                    + self.type.m.m  # m=m_x
                    + self.type.s.s  # s=s_x
                )
                self.size += 3
            elif m == 'v':
                if self.type.x:
                    self.size += 1
                self.type = ExpressionType(
                    # <x> VERIFY
                    'fx' + self.type.B.V  # V=B_x
                    + self.type.z.z  # z=z_x
                    + self.type.o.o  # o=o_x
                    + self.type.n.n  # n=n_x
                    + self.type.m.m  # m=m_x
                    + self.type.s.s  # s=s_x
                )
            elif m == 'j':
                self.type = ExpressionType(
                    # SIZE 0NOTEQUAL IF <x> ENDIF
                    'ndx' + (self.type.Bn).B  # B=B_x*n_x
                    + self.type.f.e  # e=f_x
                    + self.type.o.o  # o=o_x
                    + self.type.u.u  # u=u_x
                    + self.type.m.m  # m=m_x
                    + self.type.s.s  # s=s_x
                )
                self.size += 4
            elif m == 'n':
                self.type = ExpressionType(
                    # <x> 0NOTEQUAL
                    'ux' + self.type.B.B  # B=B_x
                    + self.type.z.z  # z=z_x
                    + self.type.o.o  # o=o_x
                    + self.type.n.n  # n=n_x
                    + self.type.d.d  # d=d_x
                    + self.type.f.f  # f=f_x
                    + self.type.e.e  # e=e_x
                    + self.type.m.m  # m=m_x
                    + self.type.s.s  # s=s_x
                )
                self.size += 1
            elif m in ('l', 'u'):
                self.type = ExpressionType(
                    # IF 0 ELSE <x> ENDIF/IF <x> ELSE 0 ENDIF
                    'dx' + self.type.B.B  # B=B_x
                    + self.type.u.u  # u=u_x
                    + self.type.m.m  # m=m_x
                    + self.type.s.s  # s=s_x
                    + self.type.z.o  # o=z_x
                    + self.type.f.e  # e=f_x
                )
                self.size += 4
            elif m == 't':
                self.type = ExpressionType(
                    # <x> 1
                    'fux' + self.type.V.B  # B=V_x
                    + self.type.z.z  # z=z_x
                    + self.type.o.o  # o=o_x
                    + self.type.d.d  # d=d_x
                    + self.type.m.m  # m=m_x
                    + self.type.s.s  # s=s_x
                )
                self.size += 1
        return self.type
