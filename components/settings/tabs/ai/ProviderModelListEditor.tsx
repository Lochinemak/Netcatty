import React, { useState } from "react";
import { Plus, X } from "lucide-react";
import { useI18n } from "../../../../application/i18n/I18nProvider";
import { Button } from "../../../ui/button";
import { ModelSelector } from "./ModelSelector";
import type { FetchedModel } from "./types";

type SelectorProps = Omit<
  React.ComponentProps<typeof ModelSelector>,
  "value" | "onChange" | "onEnter" | "selectedIds" | "placeholder"
>;

/** Append `id` (trimmed) unless blank, the default model, or already listed. */
export function addProviderModelId(
  models: readonly string[],
  id: string,
  defaultModel?: string,
): string[] {
  const trimmed = id.trim();
  if (!trimmed || trimmed === defaultModel?.trim() || models.includes(trimmed)) {
    return [...models];
  }
  return [...models, trimmed];
}

/**
 * The extra models a provider offers in the composer's model switcher, on top
 * of the default model. Typed ids and picks from the discovered list both add.
 */
export const ProviderModelListEditor: React.FC<SelectorProps & {
  models: string[];
  defaultModel?: string;
  onModelsChange: (models: string[]) => void;
}> = ({ models, defaultModel, onModelsChange, onModelMetadata, ...selectorProps }) => {
  const { t } = useI18n();
  const [draft, setDraft] = useState("");

  const add = (id: string) => {
    onModelsChange(addProviderModelId(models, id, defaultModel));
    setDraft("");
  };

  return (
    <div className="space-y-1.5">
      {models.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {models.map((id) => (
            <span
              key={id}
              className="inline-flex max-w-full items-center gap-1 rounded-md border border-border/60 bg-muted/40 py-0.5 pl-2 pr-1 text-xs font-mono"
            >
              <span className="truncate" title={id}>{id}</span>
              <button
                type="button"
                aria-label={t("ai.providers.models.remove").replace("{id}", id)}
                onClick={() => onModelsChange(models.filter((item) => item !== id))}
                className="rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
              >
                <X size={11} />
              </button>
            </span>
          ))}
        </div>
      )}
      <div className="flex items-start gap-2">
        <div className="flex-1 min-w-0">
          <ModelSelector
            {...selectorProps}
            value={draft}
            onChange={setDraft}
            onEnter={() => add(draft)}
            selectedIds={defaultModel ? [...models, defaultModel] : models}
            placeholder={t("ai.providers.models.placeholder")}
            onModelMetadata={(model: FetchedModel) => {
              onModelMetadata?.(model);
              add(model.id);
            }}
          />
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => add(draft)}
          disabled={!draft.trim()}
          className="shrink-0 px-2"
          aria-label={t("ai.providers.models.add")}
        >
          <Plus size={14} />
        </Button>
      </div>
    </div>
  );
};
