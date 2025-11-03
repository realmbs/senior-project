import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
	// Consult https://svelte.dev/docs/kit/integrations
	// for more information about preprocessors
	preprocess: vitePreprocess(),

	kit: {
		// Static adapter for S3/CloudFront deployment
		adapter: adapter({
			pages: 'build',
			assets: 'build',
			fallback: 'index.html', // SPA mode for S3 hosting
			precompress: false,
			strict: true
		}),
		// Disable SSR for S3 compatibility
		prerender: {
			entries: []
		}
	}
};

export default config;
