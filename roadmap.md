# Runner startup repair

- [x] Route runtime Lovable AI requests through the shared-secret cloud gateway.
- [x] Restore the missing metrics table with admin-only reads.
- [x] Test authentication and error handling; prepare an updated runner package.
- [ ] Verify successful live inference and an Oracle scan after AI credits are restored and the VPS source is updated.

# Deprecated Gateway model migration

- [x] Replace deprecated Flash and Flash Lite selections in application source.
- [x] Run routing regressions and transport tests (29 passed; preview build OK).
- [ ] Verify representative live inference (Gateway returned 402 insufficient credits; stopped further calls).
- [ ] Verify live session defaults and an authenticated affected flow (Cloud database currently unavailable).
- [ ] Update Oracle runner installation (requires user rebuilding the VPS container).