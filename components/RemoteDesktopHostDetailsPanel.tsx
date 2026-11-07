/**
 * Remote Desktop Host Details Panel
 * Dedicated editor for VNC / RDP vault hosts. These are graphical sessions,
 * so none of the SSH sections of HostDetailsPanel (keys, jump hosts, startup
 * commands, terminal theme...) apply.
 */
import { Monitor, Save } from 'lucide-react';
import React, { useMemo, useState } from 'react';
import { useI18n } from '../application/i18n/I18nProvider';
import type { Host } from '../domain/models';
import {
  REMOTE_DESKTOP_DEFAULT_PORTS,
  createRemoteDesktopHost,
  type RemoteDesktopProtocol,
} from '../domain/remoteDesktop';

import { Button } from './ui/button';
import { Combobox, ComboboxOption } from './ui/combobox';
import { Input } from './ui/input';
import { Label } from './ui/label';
import {
  AsidePanel,
  AsidePanelContent,
  AsidePanelFooter,
  type AsidePanelLayout,
  type AsidePanelResizeProps,
} from './ui/aside-panel';
import { cn } from '../lib/utils';

interface RemoteDesktopHostDetailsPanelProps {
  /** The host being edited, or the unsaved draft of a new one. */
  initialData: Host;
  protocol: RemoteDesktopProtocol;
  /** True while `initialData` is a draft that is not in the vault yet. */
  isNew: boolean;
  groups?: string[];
  onSave: (host: Host) => void;
  /** Saves the host and immediately opens it. */
  onSaveAndConnect?: (host: Host) => void;
  onCancel: () => void;
  layout?: AsidePanelLayout;
  className?: string;
}

type RemoteDesktopHostDetailsPanelPropsWithResize =
  RemoteDesktopHostDetailsPanelProps & AsidePanelResizeProps;

/** Parse a port field: empty means "use the default", anything else must be 1-65535. */
export function parseRemoteDesktopPortInput(value: string): { port?: number; valid: boolean } {
  const trimmed = value.trim();
  if (trimmed === '') return { valid: true };
  if (!/^\d+$/.test(trimmed)) return { valid: false };
  const port = Number(trimmed);
  return port >= 1 && port <= 65535 ? { port, valid: true } : { valid: false };
}

export const RemoteDesktopHostDetailsPanel: React.FC<RemoteDesktopHostDetailsPanelPropsWithResize> = ({
  initialData,
  protocol,
  isNew,
  groups = [],
  onSave,
  onSaveAndConnect,
  onCancel,
  layout = 'overlay',
  className,
  resizable,
  persistWidthStorageKey,
  resizeAriaLabel,
}) => {
  const { t } = useI18n();
  const isRdp = protocol === 'rdp';
  const defaultPort = REMOTE_DESKTOP_DEFAULT_PORTS[protocol];

  const [label, setLabel] = useState(isNew ? '' : initialData.label ?? '');
  const [hostname, setHostname] = useState(initialData.hostname ?? '');
  const [port, setPort] = useState(
    initialData.port && initialData.port !== defaultPort ? String(initialData.port) : '',
  );
  const [username, setUsername] = useState(initialData.username ?? '');
  const [password, setPassword] = useState(initialData.password ?? '');
  const [domain, setDomain] = useState(initialData.rdpDomain ?? '');
  const [group, setGroup] = useState(initialData.group ?? '');

  const parsedPort = parseRemoteDesktopPortInput(port);
  const canSave = hostname.trim() !== '' && parsedPort.valid;

  const groupOptions: ComboboxOption[] = useMemo(() => {
    const allGroups = new Set(groups);
    if (group && !allGroups.has(group)) allGroups.add(group);
    return Array.from(allGroups).map((g) => ({ value: g, label: g }));
  }, [groups, group]);

  const buildHost = (): Host => {
    const host = createRemoteDesktopHost({
      id: initialData.id,
      protocol,
      label,
      hostname,
      port: parsedPort.port,
      username,
      password,
      domain,
      group,
      tags: initialData.tags,
    });
    // Merge over the opened host so fields this form does not expose
    // (pinned, notes, order, lastConnectedAt...) survive a save.
    return { ...initialData, ...host, createdAt: initialData.createdAt ?? host.createdAt };
  };

  const handleSave = () => {
    if (canSave) onSave(buildHost());
  };
  const handleSaveAndConnect = () => {
    if (canSave && onSaveAndConnect) onSaveAndConnect(buildHost());
  };

  const idPrefix = `remote-desktop-${protocol}`;

  return (
    <AsidePanel
      open={true}
      onClose={onCancel}
      title={t(isNew ? `remoteDesktop.panel.title.new.${protocol}` : `remoteDesktop.panel.title.edit.${protocol}`)}
      subtitle={isNew ? undefined : initialData.label}
      className={cn('z-40', className)}
      layout={layout}
      dataSection="remote-desktop-host-details-panel"
      resizable={resizable}
      persistWidthStorageKey={persistWidthStorageKey}
      resizeAriaLabel={resizeAriaLabel}
    >
      <AsidePanelContent>
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-label`}>{t('remoteDesktop.field.label')}</Label>
          <Input
            id={`${idPrefix}-label`}
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder={t('remoteDesktop.field.labelPlaceholder')}
          />
        </div>

        <div className="flex gap-2">
          <div className="min-w-0 flex-1 space-y-2">
            <Label htmlFor={`${idPrefix}-hostname`}>{t('remoteDesktop.field.hostname')}</Label>
            <Input
              id={`${idPrefix}-hostname`}
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="192.168.1.10"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
            />
          </div>
          <div className="w-24 shrink-0 space-y-2">
            <Label htmlFor={`${idPrefix}-port`}>{t('remoteDesktop.field.port')}</Label>
            <Input
              id={`${idPrefix}-port`}
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder={String(defaultPort)}
              inputMode="numeric"
              aria-invalid={!parsedPort.valid}
              className={cn(!parsedPort.valid && 'border-destructive')}
            />
          </div>
        </div>

        {isRdp && (
          <>
            <div className="space-y-2">
              <Label htmlFor={`${idPrefix}-username`}>{t('remoteDesktop.field.username')}</Label>
              <Input
                id={`${idPrefix}-username`}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Administrator"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${idPrefix}-domain`}>{t('remoteDesktop.field.domain')}</Label>
              <Input
                id={`${idPrefix}-domain`}
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder={t('remoteDesktop.field.domainPlaceholder')}
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
              />
            </div>
          </>
        )}

        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-password`}>{t('remoteDesktop.field.password')}</Label>
          <Input
            id={`${idPrefix}-password`}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="off"
          />
          <p className="text-xs text-muted-foreground">
            {t(isRdp ? 'remoteDesktop.field.passwordHint.rdp' : 'remoteDesktop.field.passwordHint.vnc')}
          </p>
        </div>

        <div className="space-y-2">
          <Label>{t('hostDetails.group')}</Label>
          <Combobox
            options={groupOptions}
            value={group}
            onValueChange={setGroup}
            placeholder={t('hostDetails.selectGroup')}
            allowCreate
            createText={t('hostDetails.createGroup')}
          />
        </div>
      </AsidePanelContent>

      <AsidePanelFooter>
        <div className="flex gap-2">
          <Button variant="ghost" onClick={onCancel} className="flex-1">
            {t('common.cancel')}
          </Button>
          {onSaveAndConnect && isNew && (
            <Button onClick={handleSaveAndConnect} className="flex-1" disabled={!canSave}>
              <Monitor size={14} className="mr-2" />
              {t('remoteDesktop.saveAndConnect')}
            </Button>
          )}
          <Button onClick={handleSave} className="flex-1" disabled={!canSave}>
            <Save size={14} className="mr-2" />
            {t('common.save')}
          </Button>
        </div>
      </AsidePanelFooter>
    </AsidePanel>
  );
};

export default RemoteDesktopHostDetailsPanel;
