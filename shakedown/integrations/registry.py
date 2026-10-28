"""The provider registry. The UI lists providers from here and derives its actions from each provider's declared capabilities.

A provider with `implemented=False` is shown as planned and has no connection wizard: it is a statement of intent, not a feature."""
from shakedown.integrations.adapters.splunk import SplunkCloudAdapter, SplunkEnterpriseAdapter
from shakedown.integrations.base import PLANNED, IntegrationError, ProviderAdapter, ProviderSpec

PLANNED_SPECS = (
    ProviderSpec(id="qradar", name="IBM QRadar", status=PLANNED, implemented=False, verification_note="No adapter exists. Not implemented.",
                 summary="Planned. The adapter interface is designed so a QRadar adapter can be added; none has been written or tested."),
)


class Registry:
    def __init__(self, adapters: list[ProviderAdapter], planned=PLANNED_SPECS):
        self._adapters = {a.spec.id: a for a in adapters}
        self._planned = {s.id: s for s in planned}

    def adapter(self, provider_id: str) -> ProviderAdapter:
        if provider_id in self._planned:
            raise IntegrationError("unavailable", f"{self._planned[provider_id].name} is planned and has no adapter yet")
        try:
            return self._adapters[provider_id]
        except KeyError:
            raise IntegrationError("not_found", "unknown provider") from None

    def specs(self) -> list[dict]:
        return [a.spec.public() for a in self._adapters.values()] + [s.public() for s in self._planned.values()]

    def spec(self, provider_id: str) -> ProviderSpec:
        if provider_id in self._planned:
            return self._planned[provider_id]
        return self.adapter(provider_id).spec


def default_registry() -> Registry:
    adapters: list[ProviderAdapter] = [SplunkEnterpriseAdapter(), SplunkCloudAdapter()]
    try:  # Elastic and Sentinel adapters arrive in later slices; the registry works without them
        from shakedown.integrations.adapters.elastic import ElasticAdapter
        adapters.append(ElasticAdapter())
    except ImportError:
        pass
    try:
        from shakedown.integrations.adapters.sentinel import SentinelAdapter
        adapters.append(SentinelAdapter())
    except ImportError:
        pass
    return Registry(adapters)
