# Require one final AGENTS.md completion review before Codex stops.
# The second Stop event has stop_hook_active=true and is allowed through to
# prevent an infinite continuation loop.

$raw = [Console]::In.ReadToEnd()

try {
    $payload = $raw | ConvertFrom-Json
}
catch {
    Write-Output '{}'
    exit 0
}

if ($payload.stop_hook_active -eq $true) {
    Write-Output '{}'
    exit 0
}

$reason = @"
Before stopping, perform one final OpenAssetWatch completion pass. Re-read the applicable AGENTS.md definition of done and verify the final diff, tests/validation evidence, security/privacy/licensing implications, documentation, temporary artifacts, and remaining blockers. If anything required by the assigned task is incomplete and can be completed safely within scope, continue the work and fix it now. Do not create unrelated work. If the task is complete, summarize only validation actually observed and any checks still pending.
"@.Trim()

@{
    decision = 'block'
    reason   = $reason
} | ConvertTo-Json -Compress

exit 0
