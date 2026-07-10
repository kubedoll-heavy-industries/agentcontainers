import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://agentcontainers.dev',
  integrations: [
    starlight({
      title: 'agentcontainers',
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/Kubedoll-Heavy-Industries/agentcontainers',
        },
      ],
      sidebar: [
        {
          label: 'Getting Started',
          items: [
            { label: 'Quickstart', slug: 'getting-started/quickstart' },
            { label: 'Configuration', slug: 'getting-started/configuration' },
            { label: 'Migrating from devcontainers', slug: 'getting-started/from-devcontainers', badge: 'Coming Soon' },
          ],
        },
        {
          label: 'Concepts',
          items: [
            { label: 'Architecture', slug: 'concepts/architecture' },
            { label: 'Threat Model', slug: 'concepts/threat-model' },
            { label: 'Capabilities', slug: 'concepts/capabilities', badge: 'Coming Soon' },
            { label: 'Provenance', slug: 'concepts/provenance', badge: 'Coming Soon' },
            { label: 'Enforcement', slug: 'concepts/enforcement' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Schema Reference', slug: 'reference/schema' },
            { label: 'CLI Reference', slug: 'reference/cli' },
            { label: 'MCP Tools', slug: 'reference/mcp-tools', badge: 'Coming Soon' },
          ],
        },
        {
          label: 'Guides',
          items: [
            { label: 'Secrets Management', slug: 'guides/secrets' },
            { label: 'Organization Policy', slug: 'guides/org-policy' },
            { label: 'Securing Claude Code', slug: 'guides/securing-claude-code', badge: 'Coming Soon' },
            { label: 'CI/CD Integration', slug: 'guides/ci-cd-integration', badge: 'Coming Soon' },
          ],
        },
        {
          label: 'Project',
          items: [
            { label: 'Roadmap', slug: 'project/roadmap' },
            { label: 'Contributing', slug: 'project/contributing' },
            { label: 'Security', slug: 'project/security' },
          ],
        },
      ],
    }),
  ],
});
