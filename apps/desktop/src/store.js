/**
 * Persistent store for app settings (main process only).
 * Uses electron-store; keys: cliPathOverride (string | undefined).
 */
import Store from 'electron-store';

const store = new Store({
  name: 'promptheus-desktop',
});

export function getCliPathOverride() {
  return store.get('cliPathOverride');
}

export function setCliPathOverride(value) {
  if (value === undefined || value === '') {
    store.delete('cliPathOverride');
  } else {
    store.set('cliPathOverride', value);
  }
}
