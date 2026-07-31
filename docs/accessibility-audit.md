# Accessibility Audit

Assessment date: 16 July 2026. Scope: React dashboard and static project
website. Target: practical alignment with WCAG 2.2 AA; this is not a formal
conformance certification.

## Controls added

- A keyboard-visible skip link targets the dashboard's main content.
- Primary navigation and mobile navigation have accessible names.
- Decorative navigation icons are hidden from assistive technology.
- Icon-only close and status actions have accessible labels.
- Popovers and connection errors expose dialog semantics and names.
- Scan results and backend connectivity expose polite live status updates.
- The off-screen mobile navigation is inert while closed.
- A source-level CI check rejects positive tab order, non-semantic clickable
  `div`/`span` elements, missing image alternative text, and missing document
  language.

## Keyboard review

The expected keyboard path is: skip link, mobile menu when present, language
selector, scan control, primary navigation, then page content. Native buttons,
links, inputs and selects retain browser focus behavior. Escape handling remains
available in the scan input. A full screen-reader/browser matrix remains a
release-quality follow-up rather than a claim made by this audit.

## Known limitations

- Some data visualizations need separate screen-reader summaries as their
  components evolve.
- Focus trapping and restoration for every future modal must be checked during
  component review.
- Colour contrast should be rechecked whenever theme tokens change.
- The static website has its own editing surface and needs repeat manual review
  when that interface changes.

Run `npm run test:a11y` from `frontend/` for the automated source checks.
