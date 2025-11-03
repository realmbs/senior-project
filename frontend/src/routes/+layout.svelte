<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import NavBar from '$lib/components/NavBar.svelte';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Threat Intelligence Platform</title>
	<meta name="description" content="Automated OSINT threat intelligence collection and analysis platform" />
</svelte:head>

<div class="main-content">
	<!-- Navigation Bar -->
	<NavBar />

	<!-- Sidebar -->
	<Sidebar />

	<!-- Main Content Area -->
	<main class="main-content-inner">
		{@render children()}
	</main>
</div>
