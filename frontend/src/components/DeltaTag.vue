<template>
  <span v-if="prev === undefined" class="delta muted">（新）</span>
  <span v-else-if="cur === prev" class="delta flat">＝0</span>
  <span v-else :class="cur > prev ? 'delta up' : 'delta down'">
    {{ cur > prev ? '↑' : '↓' }}{{ Math.abs(cur - prev) }}
  </span>
</template>

<script setup lang="ts">
defineProps<{ cur: number; prev?: number }>()
</script>

<style scoped>
.delta{font-size:10px;margin-left:3px}
.delta.up{color:#f87171}
.delta.down{color:#4ade80}
.delta.flat{color:#64748b}
.muted{color:#64748b}
</style>
