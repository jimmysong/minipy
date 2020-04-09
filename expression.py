# B Base: pushes non-zero to stack when satsified, zero to stack when not
# V Verify: leaves nothing new on stack when satisfied, exits otherwise
# K Key: pushes a pubkey to the stack, needs sig to satisfy
# W Wrapped: inputs come from below the top element acts like B
# z Zero: consumes 0 elements from the stack
# o One: consumes 1 element from the stack
# n Nonzero: top element on stack does not need to be zero
# d Dissatisfiable: can run without satisfying or exiting script
# u Unit: puts exactly a 1 on the stack when satisfied
# e Expression: dissatisfiable and nonmalleable
# f Forced: dissatisfying requires a signature
# s Safe: satisfying requires a signature
# m Nonmalleable: satisfying can be done so it's nonmalleable
# x Expensive: requires 1 more byte to make into V expression
EXPRESSION_TYPE_ALPHABET = 'BVKWzonduefsmx'


class BetterBool:
    def __init__(self, b):
        if type(b) != bool:
            raise TypeError('initialize with bool')
        self.b = b

    def __add__(self, other):
        if type(other) == bool:
            o = self.__class__(other)
        else:
            o = other
        return self.__class__(self.b or o.b)

    def __bool__(self):
        return self.b

    def __getattr__(self, attribute):
        if self.b:
            return attribute
        else:
            return ''

    def __mul__(self, other):
        if type(other) == bool:
            o = self.__class__(other)
        else:
            o = other
        return self.__class__(self.b and o.b)


class ExpressionType(set):
    def __new__(cls, s):
        result = []
        for letter in s:
            if letter not in EXPRESSION_TYPE_ALPHABET:
                raise KeyError('Not a valid type')
            result.append(letter)
        e = super().__new__(cls, result)
        if e.z and e.o:
            raise TypeError('Cannot consume both 1 and 0 arguments')
        if e.n and e.z:
            raise TypeError(
                'Cannot consume both 0 elements and 1 or more elements')
        if e.V and e.d:
            raise TypeError(
                'Verifying expressions halt and are not dissatisfiable')
        if e.K and not e.u:
            raise TypeError('Key expressions are also unit expressions')
        if e.V and e.u:
            raise TypeError(
                'Verifying expressions do not push anything back so are not unit expressions'
            )
        if e.e and e.f:
            raise TypeError(
                'Dissatisfactions cannot both be non-malleable and also have at least one signature'
            )
        if e.e and not e.d:
            raise TypeError(
                'Non-malleable Dissatisfactions imply dissatisfiability')
        if e.V and e.e:
            raise TypeError('Verifying expressions are not dissatisfiable')
        if e.d and e.f:
            raise TypeError('Dissatisfiability implies no signature is needed')
        if e.V and not e.f:
            raise TypeError(
                'Verifying expressions have no dissatisfactions, meaning it is forced'
            )
        if e.K and not e.s:
            raise TypeError('Key expressions always require a signature')
        if e.z and not e.m:
            raise TypeError(
                'Zero arguments being consumed imply non-malleability')
        return e

    def __repr__(self):
        result = ''
        for letter in EXPRESSION_TYPE_ALPHABET:
            if letter in self:
                result += letter
        return result

    def __getattr__(self, attribute):
        for l in attribute:
            if l not in self:
                return BetterBool(False)
        return BetterBool(True)
