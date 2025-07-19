[Environment]::SetEnvironmentVariable('RESUME_RELEASE', 'true', 'Process')
& .\publish_new_release.ps1 -PackageIdentifier 'deafsquad.UpdateLoxone'