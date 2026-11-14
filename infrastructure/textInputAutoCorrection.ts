/**
 * Stops the webview from rewriting what the user types.
 *
 * WKWebView (the Tauri webview on macOS) applies the system's "capitalize
 * words automatically" and "correct spelling automatically" substitutions to
 * every plain text field, so a username such as `root` or a host label such as
 * `web-01` comes out as `Root` / `Web-01`. Nothing in an SSH manager wants
 * that: hostnames, usernames, paths, commands and keys are all case-sensitive.
 *
 * There are well over a hundred text fields in the renderer, most of them raw
 * `<input>` elements, so the opt-out is applied in one place: when a field
 * takes focus, before the first keystroke. A field that sets one of these
 * attributes itself keeps its own value.
 */

type TextField = Pick<Element, 'tagName' | 'hasAttribute' | 'setAttribute' | 'getAttribute'>;

/** `<input>` types that hold free text and are therefore subject to substitution. */
const TEXT_INPUT_TYPES = new Set(['', 'text', 'search', 'url', 'email', 'tel', 'password']);

const setDefault = (field: TextField, name: string, value: string): void => {
  if (!field.hasAttribute(name)) field.setAttribute(name, value);
};

/** Returns true when `target` is a text field and the opt-outs are now in place. */
export const disableAutoCorrection = (target: unknown): boolean => {
  const field = target as TextField | null;
  if (!field || typeof field.tagName !== 'string' || typeof field.setAttribute !== 'function') {
    return false;
  }

  const tag = field.tagName.toUpperCase();
  if (tag === 'INPUT') {
    const type = (field.getAttribute('type') ?? '').toLowerCase();
    if (!TEXT_INPUT_TYPES.has(type)) return false;
    // Single-line fields hold identifiers, not prose: the spell checker is the
    // engine behind the substitutions, and its red underline is noise here.
    setDefault(field, 'spellcheck', 'false');
  } else if (tag !== 'TEXTAREA') {
    return false;
  }

  setDefault(field, 'autocapitalize', 'off');
  setDefault(field, 'autocorrect', 'off');
  return true;
};

/** Applies the opt-outs to every text field in `doc` as it gains focus. */
export const installAutoCorrectionGuard = (doc: Document = document): (() => void) => {
  const onFocusIn = (event: Event) => {
    disableAutoCorrection(event.target);
  };
  doc.addEventListener('focusin', onFocusIn, true);
  // A field that already had focus when this ran (autofocus) never fires focusin.
  disableAutoCorrection(doc.activeElement);
  return () => doc.removeEventListener('focusin', onFocusIn, true);
};
