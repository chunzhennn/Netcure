<script setup lang="ts">
defineProps<{
  label: string;
  value: string | number;
  hint?: string;
  tone?: 'neutral' | 'good' | 'warning' | 'danger';
}>();
</script>

<template>
  <article class="metric-tile" :data-tone="tone ?? 'neutral'">
    <p class="metric-tile__label">{{ label }}</p>
    <p class="metric-tile__value">{{ value }}</p>
    <p v-if="hint" class="metric-tile__hint">{{ hint }}</p>
  </article>
</template>
