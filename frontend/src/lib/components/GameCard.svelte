<script lang="ts">
	import type { main } from '$lib/wailsjs/go/models';
	import { Gamepad2 } from 'lucide-svelte';

	export let data: main.IgdbGame;
</script>

<div class="w-full relative aspect-[3/4] group" on:click on:keydown role="button" tabindex="0">
	{#if data.cover.image_id}
		<img
			src={'https://images.igdb.com/igdb/image/upload/t_cover_big/' + data.cover.image_id + '.jpg'}
			alt="cover"
			class="h-full rounded-3xl hover:opacity-30 group-hover:opacity-30 transition-opacity"
		/>
	{:else}
		<span
			class="rounded-3xl h-full hover:opacity-30 group-hover:opacity-30 transition-opacity from-primary to-secondary bg-gradient-to-br flex justify-center items-center"
		>
			<p class="select-none text-muted">
				<Gamepad2 size={64} />
			</p>
		</span>
	{/if}
	<p
		class="absolute font-heading left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity text-center font-semibold"
	>
		{data.name}
	</p>
</div>
