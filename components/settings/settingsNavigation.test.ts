import assert from "node:assert/strict";
import test from "node:test";
import { normalizeSettingsTab, settingsTabFromHash } from "./settingsNavigation";

test("settingsTabFromHash reads the tab query of the settings route", () => {
  assert.equal(settingsTabFromHash("#/settings?tab=sync"), "sync");
  assert.equal(settingsTabFromHash("#/settings?tab=file-associations"), "file-associations");
  assert.equal(settingsTabFromHash("#/settings"), null);
  assert.equal(settingsTabFromHash("#/settings?tab=unknown"), null);
});

test("normalizeSettingsTab rejects unknown values", () => {
  assert.equal(normalizeSettingsTab("ai"), "ai");
  assert.equal(normalizeSettingsTab(""), null);
  assert.equal(normalizeSettingsTab(undefined), null);
  assert.equal(normalizeSettingsTab(42), null);
});
