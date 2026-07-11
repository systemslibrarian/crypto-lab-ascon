/**
 * Shareable lesson links.
 *
 * An instructor can freeze the AEAD inputs and hash input into a URL and
 * hand the exact scenario to a class. Keys in URLs are a cardinal sin for
 * real secrets — these are classroom values, and the UI says so out loud.
 */

const HEX32 = /^[0-9a-f]{32}$/;
const MAX_TEXT = 512;

export interface ShareRefs {
  key: HTMLInputElement;
  nonce: HTMLInputElement;
  ad: HTMLInputElement;
  pt: HTMLTextAreaElement;
  hashMsg: HTMLInputElement;
}

/** Apply ?key=&nonce=&ad=&pt=&msg= from the URL. Returns true if anything loaded. */
export function applyParamsFromUrl(refs: ShareRefs): boolean {
  const params = new URLSearchParams(window.location.search);
  let applied = false;

  const key = params.get('key')?.trim().toLowerCase();
  if (key && HEX32.test(key)) {
    refs.key.value = key;
    applied = true;
  }
  const nonce = params.get('nonce')?.trim().toLowerCase();
  if (nonce && HEX32.test(nonce)) {
    refs.nonce.value = nonce;
    applied = true;
  }
  for (const [name, node] of [
    ['ad', refs.ad],
    ['pt', refs.pt],
    ['msg', refs.hashMsg],
  ] as const) {
    const value = params.get(name);
    if (value !== null && value.length <= MAX_TEXT) {
      node.value = value;
      applied = true;
    }
  }
  return applied;
}

export function buildShareUrl(refs: ShareRefs): string {
  const params = new URLSearchParams();
  params.set('key', refs.key.value.trim());
  params.set('nonce', refs.nonce.value.trim());
  if (refs.ad.value) {
    params.set('ad', refs.ad.value.slice(0, MAX_TEXT));
  }
  if (refs.pt.value) {
    params.set('pt', refs.pt.value.slice(0, MAX_TEXT));
  }
  if (refs.hashMsg.value) {
    params.set('msg', refs.hashMsg.value.slice(0, MAX_TEXT));
  }
  return `${window.location.origin}${window.location.pathname}?${params.toString()}`;
}
