# Legacy Source Review

The tool YAMLs, screenshots, UI ideas, and code patterns reviewed earlier came
from a different/source project. They are reference material only and do not
define OpenAssetWatch architecture.

OpenAssetWatch should keep or rewrite only the parts that support defensive
asset intelligence:

- passive inventory
- external exposure connectors
- evidence review
- approved diagnostics
- finding and remediation workflows
- cloud and IaC posture review
- internal result viewing

OpenAssetWatch must discard or quarantine material that behaves like a
penetration testing platform, C2 framework, exploitation framework, payload
generator, credential attack platform, webshell, terminal, or unrestricted raw
scanner launcher.

This first pass found no active legacy/source project tool YAMLs to move. The
active repository content reviewed here is mostly an early defensive collector,
backend, and documentation set. Scanner-oriented names in active defaults were
removed or redirected toward safe policy language.
