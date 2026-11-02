from stix_shifter_utils.stix_translation.src.utils.transformers import ValueTransformer


class BackslashUser(ValueTransformer):
    """The account name from ``DOMAIN\\user`` (or the value unchanged)."""

    @staticmethod
    def transform(obj):
        return str(obj).rsplit('\\', 1)[-1] if obj else obj
