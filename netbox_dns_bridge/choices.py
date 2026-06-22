from utilities.choices import ChoiceSet


class NotifyPruneStrategyChoices(ChoiceSet):
    """
    Strategy used to shed dead dynamic NOTIFY targets (SeenTransferClient rows).

    Static targets are never pruned regardless of strategy. See notify.py.
    """

    TTL = "ttl"
    FAILURES = "failures"
    NONE = "none"

    CHOICES = [
        (TTL, "Prune after no success within TTL", "blue"),
        (FAILURES, "Prune after N consecutive failures", "orange"),
        (NONE, "Never prune", "gray"),
    ]
