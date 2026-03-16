<script setup lang="ts">
defineProps<{
  eyebrow?: string;
  title: string;
  subtitle?: string;
}>();
</script>

<template>
  <section class="section-panel">
    <header class="section-panel__header">
      <p v-if="eyebrow" class="section-panel__eyebrow">{{ eyebrow }}</p>
      <h2 class="section-panel__title">{{ title }}</h2>
      <p v-if="subtitle" class="section-panel__subtitle">{{ subtitle }}</p>
    </header>
    <div class="section-panel__body">
      <slot />
    </div>
  </section>
</template>
