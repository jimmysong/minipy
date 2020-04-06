from enum import Enum, auto
from io import StringIO
from unittest import TestCase, skip

from op import *
from script import Script

TYPE_ALPHABET = 'BVKWzonduefsmx'


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


class MiniScriptTest(TestCase):
    maxDiff = None

    def test_vectors(self):
        tests = (
            ('lltvln:after(1231488000)',
             '6300676300676300670400046749b1926869516868'),
            ('uuj:and_v(v:multi(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))',
             '6363829263522103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a21025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc52af0400046749b168670068670068'
             ),
            ('or_b(un:multi(2,03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),al:older(16))',
             '63522103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee872921024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae926700686b63006760b2686c9b'
             ),
            (
                'j:and_v(vdv:after(1567547623),older(2016))',
                '829263766304e7e06e5db169686902e007b268',
            ),
            ('and_v(vu:hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),tv:sha256(ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5))',
             '6382012088aa20131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b876700686982012088a820ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc58851'
             ),
            ('t:andor(multi(3,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),v:older(4194305),v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2))',
             '532102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e2103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975562102e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd1353ae6482012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2886703010040b2696851'
             ),
            ('or_d(multi(1,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),or_b(multi(3,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a),su:after(500000)))',
             '512102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f951ae73645321022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a0121032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f2103d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a53ae7c630320a107b16700689b68'
             ),
            ('or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305)))',
             '82012088a82038df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b68773646304ff64cd1db19267006864006703010040b26868'
             ),
            ('and_v(or_i(v:multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb),v:multi(2,03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)),sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68))',
             '63522102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee52103774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb52af67522103e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a21025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc52af6882012088a820d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c6887'
             ),
            ('j:and_b(multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),s:or_i(older(1),older(4252898)))',
             '82926352210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179821024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c9752ae7c6351b26703e2e440b2689a68'
             ),
            ('and_b(older(16),s:or_d(sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),n:after(1567547623)))',
             '60b27c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87736404e7e06e5db192689a'
             ),
            ('j:and_v(v:hash160(20195b5a3d650c17f0f29f91c33f8f6335193d07),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))',
             '82926382012088a91420195b5a3d650c17f0f29f91c33f8f6335193d078882012088a82096de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c4787736460b26868'
             ),
            ('and_b(hash256(32ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac),a:and_b(hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),a:older(1)))',
             '82012088aa2032ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac876b82012088aa20131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b876b51b26c9a6c9a'
             ),
            ('thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:pk(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))',
             '522103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c721036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0052ae6b5121036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0051ae6c936b21022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01ac6c935287'
             ),
            ('and_n(sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68),t:or_i(v:older(4252898),v:older(144)))',
             '82012088a820d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68876400676303e2e440b26967029000b269685168'
             ),
            ('or_d(d:and_v(v:older(4252898),v:older(4252898)),sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6))',
             '766303e2e440b26903e2e440b26968736482012088a82038df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b68768'
             ),
            ('and_v(or_c(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),v:multi(1,02c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db)),pk(03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))',
             '82012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed28764512102c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db51af682103acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbeac'
             ),
            ('and_v(or_c(multi(2,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),v:ripemd160(1b0f3c404d12075c68c938f9f60ebea4f74941a0)),pk(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))',
             '5221036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a002102352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d552ae6482012088a6141b0f3c404d12075c68c938f9f60ebea4f74941a088682103fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556ac'
             ),
            ('and_v(andor(hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),v:hash256(939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735),v:older(50000)),after(499999999))',
             '82012088aa208a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b2587640350c300b2696782012088aa20939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735886804ff64cd1db1'
             ),
            ('andor(hash256(5f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040),j:and_v(v:hash160(3a2bff0da9d96868e66abc4427bea4691cf61ccd),older(4194305)),ripemd160(44d90e2d3714c8663b632fcf0f9d5f22192cc4c8))',
             '82012088aa205f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040876482012088a61444d90e2d3714c8663b632fcf0f9d5f22192cc4c8876782926382012088a9143a2bff0da9d96868e66abc4427bea4691cf61ccd8803010040b26868'
             ),
            ('or_i(and_v(v:after(500000),pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),sha256(d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f946))',
             '630320a107b1692102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac6782012088a820d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f9468768'
             ),
            ('thresh(2,pkh(5dedfbf9ea599dd4e3ca6a80b333c472fd0b3f69),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))',
             '76a9145dedfbf9ea599dd4e3ca6a80b333c472fd0b3f6988ac7c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87936b82012088a914dd69735817e0e3f6f826a9238dc2e291184f0131876c935287'
             ),
            ('and_n(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),u:and_v(v:older(144),pk(03fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ce)))',
             '82012088a8209267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed28764006763029000b2692103fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ceac67006868'
             ),
            ('and_n(pk(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(4252898),a:older(16)))',
             '2103daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729ac64006763006703e2e440b2686b60b26c9a68'
             ),
            ('c:or_i(and_v(v:older(16),pk_h(9fc5dbe5efdce10374a4dd4053c93af540211718)),pk_h(2fbd32c8dd59ee7c17e66cb6ebea7e9846c3040f))',
             '6360b26976a9149fc5dbe5efdce10374a4dd4053c93af540211718886776a9142fbd32c8dd59ee7c17e66cb6ebea7e9846c3040f8868ac'
             ),
            ('or_d(pkh(c42e7ef92fdb603af844d064faad95db9bcdfd3d),andor(pk(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))',
             '76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac736421024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97ac6404e7e06e5db16702e007b26868'
             ),
            ('c:andor(ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(9fc5dbe5efdce10374a4dd4053c93af540211718),and_v(v:hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),pk_h(dd100be7d9aea5721158ebde6d6a1fd8fff93bb1)))',
             '82012088a6146ad07d21fd5dfc646f0b30577045ce201616b9ba876482012088aa208a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b258876a914dd100be7d9aea5721158ebde6d6a1fd8fff93bb1886776a9149fc5dbe5efdce10374a4dd4053c93af5402117188868ac'
             ),
            ('c:andor(u:ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(20d637c1a6404d2227f3561fdbaff5a680dba648),or_i(pk_h(9652d86bedf43ad264362e6e6eba6eb764508127),pk_h(751e76e8199196d454941c45d1b3a323f1433bd6)))',
             '6382012088a6146ad07d21fd5dfc646f0b30577045ce201616b9ba87670068646376a9149652d86bedf43ad264362e6e6eba6eb764508127886776a914751e76e8199196d454941c45d1b3a323f1433bd688686776a91420d637c1a6404d2227f3561fdbaff5a680dba6488868ac'
             ),
            ('c:or_i(andor(pkh(fcd35ddacad9f2d5be5e464639441c6065e6955d),pk_h(9652d86bedf43ad264362e6e6eba6eb764508127),pk_h(06afd46bcdfd22ef94ac122aa11f241244a37ecc)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))',
             '6376a914fcd35ddacad9f2d5be5e464639441c6065e6955d88ac6476a91406afd46bcdfd22ef94ac122aa11f241244a37ecc886776a9149652d86bedf43ad264362e6e6eba6eb7645081278868672102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e68ac'
             ),
        )
        for miniscript, script_hex in tests:
            k = MiniScript.parse(StringIO(miniscript))
            self.assertEqual(k.__repr__(), miniscript)
            s = k.script()
            self.assertEqual(s.raw_serialize().hex(), script_hex, s)
            self.assertEqual(s.miniscript().__repr__(), k.__repr__())


class ExpressionType(int):
    def __new__(cls, s):
        result = 0
        for letter in s:
            if letter not in TYPE_ALPHABET:
                raise SyntaxError('Not a valid type')
            result |= (1 << TYPE_ALPHABET.index(letter))
        return super().__new__(cls, result)

    def __repr__(self):
        result = ''
        for i, letter in enumerate(TYPE_ALPHABET):
            if self & (1 << i):
                result += letter
        return result

    def __in__(self, letter):
        index = TYPE_ALPHABET.index(letter)
        return bool(self & (1 << index))
