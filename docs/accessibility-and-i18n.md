# Accessibility and Internationalization

OpenShield aims for keyboard-operable interfaces, visible focus, semantic HTML,
text alternatives for meaningful images, labeled controls, adequate contrast,
responsive layouts and reduced-motion compatibility where practical. New UI
changes should be reviewed against WCAG 2.2 AA guidance and tested with keyboard
navigation. Accessibility defects are tracked like other product defects.

English is currently the only supported interface language. User-facing text
should be kept separate from security data and logic where practical so a
future localization system can replace it without changing scanner behavior.
OpenShield must not claim full internationalization until the frontend and
website use message catalogs, locale-aware formatting and localization tests.
