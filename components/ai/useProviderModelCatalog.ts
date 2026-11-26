import { useEffect, useMemo, useRef, useState } from 'react';
import {
  fetchProviderModelCatalog,
  providerModelCacheKey,
  readCachedProviderModelCatalog,
} from '../../infrastructure/ai/cattyProviderModels';
import {
  buildProviderSeedModels,
  mergeComposerModels,
  normalizeProviderModelIds,
  type ComposerPickerModel,
} from '../../infrastructure/ai/composerPicker';
import type { ProviderConfig } from '../../infrastructure/ai/types';
import { getFetchBridge } from '../settings/tabs/ai/types';

export interface ProviderModelCatalog {
  models: ComposerPickerModel[];
  fetched: boolean;
  loading: boolean;
  error?: string;
}

interface DiscoveredCatalog {
  models: ComposerPickerModel[];
  fetched: boolean;
  error?: string;
}

const EMPTY: DiscoveredCatalog = { models: [], fetched: false };

export function useProviderModelCatalog(
  provider: ProviderConfig | undefined,
  enabled: boolean,
): ProviderModelCatalog {
  const cacheKey = provider && enabled ? providerModelCacheKey(provider) : '';
  const providerRef = useRef(provider);
  providerRef.current = provider;

  // The seed (default model, user-added models, preset list) is read from the
  // provider on every change to those fields, not only when discovery inputs
  // change, so editing the model list in Settings shows up immediately.
  const seedKey = provider && enabled
    ? JSON.stringify([provider.defaultModel ?? '', normalizeProviderModelIds(provider.models), provider.providerId])
    : '';
  const seed = useMemo(
    () => {
      const current = providerRef.current;
      return seedKey && current ? buildProviderSeedModels(current) : [];
    },
    [seedKey],
  );

  const [discovered, setDiscovered] = useState<DiscoveredCatalog>(() => {
    const current = providerRef.current;
    const hit = current && enabled ? readCachedProviderModelCatalog(current) : null;
    return hit ? { models: hit, fetched: true } : EMPTY;
  });
  const [loading, setLoading] = useState(() => {
    const current = providerRef.current;
    return Boolean(enabled && current && !readCachedProviderModelCatalog(current));
  });

  useEffect(() => {
    const current = providerRef.current;
    if (!enabled || !current) {
      setDiscovered(EMPTY);
      setLoading(false);
      return;
    }

    const hit = readCachedProviderModelCatalog(current);
    if (hit) {
      setDiscovered((prev) => (
        prev.fetched && prev.models === hit ? prev : { models: hit, fetched: true }
      ));
      setLoading(false);
      return;
    }

    let cancelled = false;
    setDiscovered(EMPTY);
    setLoading(true);
    void fetchProviderModelCatalog(current, getFetchBridge()).then((next) => {
      if (cancelled) return;
      setDiscovered(next);
      setLoading(false);
    });

    return () => {
      cancelled = true;
    };
  }, [cacheKey, enabled]);

  // Seed first: the user's own models lead, and a cache hit (which holds only
  // the discovered ids) never hides the default or user-added models.
  const models = useMemo(
    () => mergeComposerModels(seed, discovered.models),
    [seed, discovered.models],
  );

  return {
    models,
    fetched: discovered.fetched,
    loading,
    error: discovered.error,
  };
}
