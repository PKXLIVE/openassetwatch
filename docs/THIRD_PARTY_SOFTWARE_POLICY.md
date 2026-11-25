# Third-party software policy

This policy is OpenAssetWatch's engineering gate for using, distributing, or
hosting third-party software. The maintainer records each decision for the
specific version, artifact, and use. Qualified counsel reviews unclear terms
and consequential commercial uses.

## Intake and approval

1. Record the component, version, source, pinned hash or digest, and reason for
   use. Cover direct and transitive dependencies, vendored and generated code,
   embedded assets, model runtimes and weights, browser bundles, binaries,
   installer extensions, container layers, and installed OS packages. Record
   build-only tools and verify whether any of their output carries upstream code
   or notices.
2. Verify the license against the exact upstream release and the packaged
   artifact. Record the applicable SPDX expression or the full custom terms,
   copyright owners as stated upstream, exceptions, and evidence. A package
   classifier alone cannot establish the license of vendored or native code.
3. Record whether the component is imported, statically or dynamically linked,
   loaded at runtime, used as a separate process, copied into a package, or
   provided as part of a service. Record modifications, target platforms, who
   receives copies, and which upstream materials the recipient needs.
4. Apply the review categories below and record the maintainer, date, approved
   use, obligations, and any counsel decision. Unknown or custom terms fail
   closed pending documented verification and explicit approval. Keep
   unresolved components out of any proposed new distribution or hosted use.
5. Verify the final artifact contains or accompanies the required license text,
   copyright, NOTICE, attribution, source, source offers, or relinking
   materials, as applicable. Record where each item is delivered. Generate an
   SBOM from the built artifact and bind the evidence to its digest.
6. Re-review after a change in version, license, ownership, build options,
   distribution, deployment model, or bundled dependencies. When removing a
   component, verify that no copy remains in current artifacts and preserve
   obligations and evidence for earlier distributions as applicable.

| Category | Engineering decision |
| --- | --- |
| Permissive | A maintainer may approve the recorded use once the required notices, attribution, and other conditions are satisfied. |
| Weak or file-level copyleft | Explicit review before inclusion. Verify the affected files or libraries, how they are loaded or linked, modifications, and any source or relinking requirements. |
| Strong copyleft | Explicit review before linking or bundling. Evaluate separate-process use and redistribution on their own facts. |
| Network copyleft | Explicit review before hosted-service use, including the terms that apply to network interactions and source availability. |
| Proprietary, source-available, or custom | Explicit approval for the exact use after terms are verified. Route ambiguous terms and material commercial restrictions to counsel. |
| Unknown or unverified | Keep the proposed use closed until evidence resolves the license and obligations. |

The repository's dependency review denies specified GPL, LGPL, and AGPL
identifiers where that check runs. A maintainer decision under this policy
does not override CI or authorize bypassing a repository gate. Escalate any
policy conflict before accepting the dependency. Use the
[Source Licensing Registry](SOURCE_LICENSING_REGISTRY.md) for upstream datasets
and feeds, and the [distribution inventory](DISTRIBUTION_LICENSE_INVENTORY.md)
for artifact evidence.
