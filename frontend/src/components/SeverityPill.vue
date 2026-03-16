<script setup lang="ts">
import { computed } from 'vue';
import { severityLabel, severityTone } from '../report';
import type { Severity } from '../types';

const props = defineProps<{
  level: Severity;
}>();

const label = computed(() => severityLabel[props.level]);
const tone = computed(() => severityTone[props.level]);
</script>

<template>
  <span class="severity-pill" :data-tone="tone">{{ label }}</span>
</template>
