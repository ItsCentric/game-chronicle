<script lang="ts">
	import { settingsSchema, type SettingsFormSchema } from '$lib/schemas';
	import { PencilIcon, Plus, Trash } from 'lucide-svelte';
	import { superForm } from 'sveltekit-superforms';
	import * as Form from '$lib/components/ui/form';
	import * as Dialog from '$lib/components/ui/dialog';
	import * as Table from '$lib/components/ui/table';
	import { Switch } from '$lib/components/ui/switch';
	import { Button } from '$lib/components/ui/button';
	import { zod } from 'sveltekit-superforms/adapters';
	import Input from '$lib/components/ui/input/input.svelte';
	import { useMutation, useQueryClient } from '@sveltestack/svelte-query';
	import { toast } from 'svelte-sonner';
	import { saveUserSettings } from '$lib/rust-bindings/helpers';
	import { open } from '@tauri-apps/plugin-dialog';
	import { relaunch } from '@tauri-apps/plugin-process';
	import type { PageData } from './$types';
	import type { z } from 'zod';

	export let data: PageData;
	const settingsKeysThatShouldReload: (keyof z.infer<SettingsFormSchema>)[] = [
		'processMonitoringEnabled',
		'processMonitoringDirectoryDepth',
		'executablePaths',
		'autostart'
	];
	let openReloadApplicationModal = false;

	const queryClient = useQueryClient();
	const userPreferencesMutation = useMutation('userSettings', saveUserSettings, {
		onSuccess: () => {
			queryClient.invalidateQueries('userPreferences');
			for (const key of settingsKeysThatShouldReload) {
				if (Array.isArray(data.form.data[key]) && Array.isArray($settingsFormData[key])) {
					const initialArray = data.form.data[key] as unknown[];
					const newArray = $settingsFormData[key] as unknown[];
					if (initialArray.length !== newArray.length) {
						openReloadApplicationModal = true;
						break;
					}
					for (let i = 0; i < initialArray.length; i++) {
						if (initialArray[i] !== newArray[i]) {
							openReloadApplicationModal = true;
							break;
						}
					}
				} else if (data.form.data[key] !== $settingsFormData[key]) {
					openReloadApplicationModal = true;
					break;
				}
			}
		}
	});
	const settingsForm = superForm(data.form, {
		resetForm: false,
		validators: zod(settingsSchema),
		SPA: true,
		onUpdate: async ({ form }) => {
			if (form.valid) {
				var newSettings = {
					executable_paths: form.data.executablePaths.join(';'),
					username: form.data.username,
					process_monitoring: {
						enabled: form.data.processMonitoringEnabled,
						directory_depth: form.data.processMonitoringDirectoryDepth
					},
					twitch_client_id: form.data.twitchClientId,
					twitch_client_secret: form.data.twitchClientSecret,
					autostart: form.data.autostart,
					new: false
				};
				toast.promise($userPreferencesMutation.mutateAsync(newSettings), {
					loading: 'Saving new settings...',
					success: 'Settings saved successfully',
					error: 'Failed to save settings'
				});
			}
		}
	});
	const {
		form: settingsFormData,
		enhance: settingsFormEnhance,
		validate: validateSettingsFormField,
		allErrors: settingsFormErrors
	} = settingsForm;

	async function newDirectoryDialog() {
		const selectedDirectory = await open({
			directory: true,
			multiple: false
		});
		if (selectedDirectory) {
			addPath(selectedDirectory as string);
		}
	}
	async function editDirectoryDialog(pathToEdit: string) {
		const selectedDirectory = await open({
			directory: true,
			multiple: false
		});
		if (selectedDirectory) {
			removePath(pathToEdit);
			addPath(selectedDirectory as string);
		}
	}
	function removePath(path: string) {
		$settingsFormData.executablePaths = $settingsFormData.executablePaths.filter((p) => p !== path);
	}
	function addPath(path: string) {
		$settingsFormData.executablePaths = [...$settingsFormData.executablePaths, path];
	}
</script>

<main class="w-full h-full py-12 flex-col justify-center container items-center">
	<div class="flex gap-2 mb-8 items-center">
		<h1 class="text-3xl font-heading font-bold">Settings</h1>
	</div>
	<form method="post" use:settingsFormEnhance class="flex flex-col gap-8">
		<section class="flex flex-col gap-2">
			<div class="flex justify-between mb-2">
				<h2 class="text-2xl font-heading font-bold">General</h2>
			</div>
			<Form.Field form={settingsForm} name="username">
				<Form.Control let:attrs>
					<div class="flex justify-between items-center">
						<Form.Label>Username</Form.Label>
						<Input {...attrs} bind:value={$settingsFormData.username} class="max-w-xs" />
					</div>
				</Form.Control>
			</Form.Field>
			<Form.Field form={settingsForm} name="twitchClientId">
				<Form.Control let:attrs>
					<div class="flex justify-between items-center">
						<Form.Label>Client ID</Form.Label>
						<Input {...attrs} bind:value={$settingsFormData.twitchClientId} class="max-w-xs" />
					</div>
				</Form.Control>
			</Form.Field>
			<Form.Field form={settingsForm} name="twitchClientSecret">
				<Form.Control let:attrs>
					<div class="flex justify-between items-center">
						<Form.Label>Client Secret</Form.Label>
						<Input {...attrs} bind:value={$settingsFormData.twitchClientSecret} class="max-w-xs" />
					</div>
				</Form.Control>
			</Form.Field>
			<Form.Field form={settingsForm} name="autostart">
				<Form.Control let:attrs>
					<div class="flex justify-between items-center">
						<Form.Label>Open on computer startup</Form.Label>
						<Switch includeInput {...attrs} bind:checked={$settingsFormData.autostart} />
					</div>
				</Form.Control>
			</Form.Field>
		</section>
		<section class="flex flex-col gap-2">
			<div class="flex justify-between mb-2">
				<h2 class="text-2xl font-heading font-bold">Monitoring</h2>
			</div>
			<Form.Field form={settingsForm} name="processMonitoringEnabled">
				<Form.Control let:attrs>
					<div class="flex justify-between items-center">
						<Form.Label>Enable Game Monitoring</Form.Label>
						<Switch
							includeInput
							{...attrs}
							bind:checked={$settingsFormData.processMonitoringEnabled}
						/>
					</div>
				</Form.Control>
			</Form.Field>
			<Form.Field form={settingsForm} name="processMonitoringDirectoryDepth">
				<Form.Control let:attrs>
					<div class="flex justify-between items-center">
						<Form.Label>Directory Depth</Form.Label>
						<Input
							{...attrs}
							bind:value={$settingsFormData.processMonitoringDirectoryDepth}
							type="number"
							min="1"
							max="99"
							class="w-16"
							on:change={({ currentTarget }) =>
								validateSettingsFormField('processMonitoringDirectoryDepth', {
									value: parseInt(currentTarget.value)
								})}
						/>
					</div>
				</Form.Control>
			</Form.Field>
			<div class="flex justify-between items-center my-2">
				<h3 class="text-xl font-heading font-bold">Monitoring Paths</h3>
				<Button type="button" on:click={newDirectoryDialog} size="sm">
					<Plus size="1.5em" class="mr-1" />
					<p>Add Path</p>
				</Button>
			</div>
			{#if $settingsFormData.executablePaths.length !== 0}
				<Table.Root>
					<Table.Caption>Edit the system paths that should be monitored here.</Table.Caption>
					<Table.Header>
						<Table.Row>
							<Table.Head>Path</Table.Head>
							<Table.Head class="text-right">Actions</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body>
						{#each $settingsFormData.executablePaths as path}
							<Table.Row>
								<Table.Cell class="w-3/4">{path}</Table.Cell>
								<Table.Cell class="text-right">
									<Button
										type="button"
										size="icon"
										class="mr-1"
										on:click={async () => await editDirectoryDialog(path)}
										><PencilIcon size={16} /></Button
									>
									<Button type="button" size="icon" on:click={() => removePath(path)}
										><Trash size={16} /></Button
									>
								</Table.Cell>
							</Table.Row>
						{/each}
					</Table.Body>
				</Table.Root>
			{:else}
				<Table.Root class="relative">
					<Table.Header>
						<Table.Row>
							<Table.Head>Path</Table.Head>
							<Table.Head class="text-right">Actions</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body>
						{#each Array(3) as _}
							<Table.Row>
								<Table.Cell class="w-3/4"
									><span class="w-64 h-4 bg-white/5 block rounded-xl" /></Table.Cell
								>
								<Table.Cell class="text-right">
									<Button type="button" size="icon" class="mr-1" disabled
										><PencilIcon size={16} /></Button
									>
									<Button type="button" size="icon" disabled><Trash size={16} /></Button>
								</Table.Cell>
							</Table.Row>
						{/each}
					</Table.Body>
					<div
						class="absolute top-0 left-0 bg-black/30 rounded-xl w-full h-full flex justify-center items-center"
					>
						<p class="text-lg font-semibold font-heading">No paths found, try adding some!</p>
					</div>
				</Table.Root>
			{/if}
		</section>
		<div class="flex justify-end gap-2">
			<Button type="submit" disabled={$settingsFormErrors.length > 0}>Save</Button>
			<Button
				variant="destructive"
				type="reset"
				on:click={() => window.history.back()}
				disabled={($settingsFormData.twitchClientId === '' ||
					$settingsFormData.twitchClientSecret === '') &&
					(data.form.data.twitchClientId === '' || data.form.data.twitchClientSecret === '')}
				>Cancel</Button
			>
		</div>
	</form>
	<Dialog.Root bind:open={openReloadApplicationModal}>
		<Dialog.Content>
			<Dialog.Header>
				<Dialog.Title>Take a Refresher</Dialog.Title>
				<Dialog.Description>
					Looks like you changed some settings that require a reload to go into effect, please
					reload at your earliest convenience.
				</Dialog.Description>
			</Dialog.Header>
			<Dialog.Footer>
				<Button on:click={async () => await relaunch()}>Reload now</Button>
				<Button on:click={() => (openReloadApplicationModal = false)}>I'll wait</Button>
			</Dialog.Footer>
		</Dialog.Content>
	</Dialog.Root>
</main>
