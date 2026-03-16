import { createApp } from 'vue';
import App from './App.vue';
import { parseEmbeddedReport } from './report';
import './styles.css';

const mountEl = document.getElementById('app');

function renderBootError(message: string): void {
  if (!mountEl) {
    return;
  }

  mountEl.innerHTML = `
    <div class="netcure-boot">
      <div class="netcure-boot__panel netcure-boot__panel--error">
        <h1>Netcure report failed to initialize</h1>
        <p>${message}</p>
      </div>
    </div>
  `;
}

try {
  const report = parseEmbeddedReport();

  if (!mountEl) {
    throw new Error('Application mount node is missing.');
  }

  createApp(App, { report }).mount(mountEl);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  renderBootError(message);
}
