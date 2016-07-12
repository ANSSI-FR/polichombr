'''

    === Polichombr ===

    Generic information (enum, etc.).
    Updated: 2016-05-12

'''


class TLPLevel:
    """
    TLP sensibility level. https://www.us-cert.gov/tlp
    BLACK level: "Keep the information private", should not be exported.
    """
    (
        TLPWHITE,
        TLPGREEN,
        TLPAMBER,
        TLPRED,
        TLPBLACK
    ) = range(1, 6)

    @classmethod
    def tostring(cls, val):
        for k, v in vars(cls).iteritems():
            if v == val:
                return k
        return ""

    @classmethod
    def fromstring(cls, val):
        return getattr(cls, s, None)
