// Copyright 2021 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package raw

import (
	"fmt"
	"io"
	"maps"
	"strings"

	"github.com/ossf/scorecard/v5/checker"
	"github.com/ossf/scorecard/v5/checks/fileparser"
	"github.com/ossf/scorecard/v5/checks/raw/github"
	"github.com/ossf/scorecard/v5/clients"
	"github.com/ossf/scorecard/v5/config"
	sce "github.com/ossf/scorecard/v5/errors"
	"github.com/ossf/scorecard/v5/finding"
	"github.com/ossf/scorecard/v5/internal/ghworkflow"
)

type permission string

const (
	permissionStatuses       = permission("statuses")
	permissionChecks         = permission("checks")
	permissionSecurityEvents = permission("security-events")
	permissionDeployments    = permission("deployments")
	permissionContents       = permission("contents")
	permissionPackages       = permission("packages")
	permissionActions        = permission("actions")
)

var permissionsOfInterest = []permission{
	permissionStatuses, permissionChecks,
	permissionSecurityEvents, permissionDeployments,
	permissionContents, permissionPackages, permissionActions,
}

type permissionCbData struct {
	repoClient    clients.RepoClient
	allowedWrites []config.AllowedWrite
	// calledWrites caches the write permissions that each local reusable workflow declares.
	calledWrites map[string]map[permission]bool
	results      checker.TokenPermissionsData
}

// TokenPermissions runs Token-Permissions check.
func TokenPermissions(c *checker.CheckRequest) (checker.TokenPermissionsData, error) {
	// data is shared across all GitHub workflows.
	data := permissionCbData{
		repoClient:    c.RepoClient,
		allowedWrites: c.Config.TokenPermissions.AllowedWrites,
		calledWrites:  make(map[string]map[permission]bool),
	}

	err := fileparser.OnMatchingFileContentDo(c.RepoClient, fileparser.PathMatcher{
		Pattern:       ".github/workflows/*",
		CaseSensitive: false,
	}, validateGitHubActionTokenPermissions, &data)

	return data.results, err
}

// Check file content.
var validateGitHubActionTokenPermissions fileparser.DoWhileTrueOnFileContent = func(path string,
	content []byte,
	args ...interface{},
) (bool, error) {
	if !fileparser.IsWorkflowFile(path) {
		return true, nil
	}
	// Verify the type of the data.
	if len(args) != 1 {
		return false, fmt.Errorf(
			"validateGitHubActionTokenPermissions requires exactly 2 arguments: %w", errInvalidArgLength)
	}
	pdata, ok := args[0].(*permissionCbData)
	if !ok {
		return false, fmt.Errorf(
			"validateGitHubActionTokenPermissions requires arg[0] of type *permissionCbData: %w", errInvalidArgType)
	}

	if !fileparser.CheckFileContainsCommands(content, "#") {
		return true, nil
	}

	pdata.results.NumTokens += 1

	workflow, errs := ghworkflow.Parse(content)
	if len(errs) > 0 && workflow == nil {
		return false, fileparser.FormatActionlintError(errs)
	}

	// 1. Top-level permission definitions.
	//nolint:lll
	// https://docs.github.com/en/actions/reference/authentication-in-a-workflow#example-1-passing-the-github_token-as-an-input,
	// https://github.blog/changelog/2021-04-20-github-actions-control-permissions-for-github_token/,
	// https://docs.github.com/en/actions/reference/authentication-in-a-workflow#modifying-the-permissions-for-the-github_token.
	if err := validateTopLevelPermissions(workflow, path, pdata); err != nil {
		return false, err
	}

	// 2. Run-level permission definitions,
	// see https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#jobsjob_idpermissions.
	ignoredPermissions := createIgnoredPermissions(workflow, path, pdata)

	if err := validatejobLevelPermissions(workflow, path, pdata, ignoredPermissions); err != nil {
		return false, err
	}

	// TODO(laurent): 2. Identify github actions that require write and add checks.

	// TODO(laurent): 3. Read a few runs and ensures they have the same permissions.

	return true, nil
}

func validatePermission(permissionKey permission, permissionValue *ghworkflow.PermissionScope,
	permLoc checker.PermissionLocation, path string, p *permissionCbData,
	ignoredPermissions map[permission]bool,
) error {
	if permissionValue.Value == nil {
		return sce.WithMessage(sce.ErrScorecardInternal, errInvalidGitHubWorkflow.Error())
	}
	key := string(permissionKey)
	val := permissionValue.Value.Value
	lineNumber := fileparser.GetLineNumber(permissionValue.Value.Pos)
	if strings.EqualFold(val, "write") {
		if isPermissionOfInterest(permissionKey, ignoredPermissions) {
			p.results.TokenPermissions = append(p.results.TokenPermissions,
				checker.TokenPermission{
					File: &checker.File{
						Path:    path,
						Type:    finding.FileTypeSource,
						Offset:  lineNumber,
						Snippet: val,
					},
					LocationType: &permLoc,
					Name:         &key,
					Value:        &val,
					Type:         checker.PermissionLevelWrite,
					// TODO: Job
				})
		} else {
			// Only log for debugging, otherwise
			// it may confuse users.
			p.results.TokenPermissions = append(p.results.TokenPermissions,
				checker.TokenPermission{
					File: &checker.File{
						Path:    path,
						Type:    finding.FileTypeSource,
						Offset:  lineNumber,
						Snippet: val,
					},
					LocationType: &permLoc,
					Name:         &key,
					Value:        &val,
					// It's a write but not considered dangerous.
					Type: checker.PermissionLevelUnknown,
					// TODO: Job
				})
		}
		return nil
	}

	p.results.TokenPermissions = append(p.results.TokenPermissions,
		checker.TokenPermission{
			File: &checker.File{
				Path:   path,
				Type:   finding.FileTypeSource,
				Offset: lineNumber,
				// TODO: set Snippet.
			},
			LocationType: &permLoc,
			Name:         &key,
			Value:        &val,
			Type:         typeOfPermission(val),
			// TODO: Job
		})
	return nil
}

func typeOfPermission(val string) checker.PermissionLevel {
	switch val {
	case "read", "read-all":
		return checker.PermissionLevelRead
	case "none": //nolint:goconst
		return checker.PermissionLevelNone
	}
	return checker.PermissionLevelUnknown
}

func validateMapPermissions(scopes map[string]*ghworkflow.PermissionScope, permLoc checker.PermissionLocation,
	path string, pdata *permissionCbData,
	ignoredPermissions map[permission]bool,
) error {
	for key, v := range scopes {
		if err := validatePermission(permission(key), v, permLoc, path, pdata, ignoredPermissions); err != nil {
			return err
		}
	}
	return nil
}

func validatePermissions(permissions *ghworkflow.Permissions, permLoc checker.PermissionLocation,
	path string, pdata *permissionCbData,
	ignoredPermissions map[permission]bool,
) error {
	allIsSet := permissions != nil && permissions.All != nil && permissions.All.Value != ""
	scopeIsSet := permissions != nil && len(permissions.Scopes) > 0
	none := "none"
	if permissions == nil || (!allIsSet && !scopeIsSet) {
		pdata.results.TokenPermissions = append(pdata.results.TokenPermissions,
			checker.TokenPermission{
				File: &checker.File{
					Path:   path,
					Type:   finding.FileTypeSource,
					Offset: checker.OffsetDefault,
				},
				LocationType: &permLoc,
				Type:         checker.PermissionLevelNone,
				Value:        &none,
				// TODO: Job, etc.
			})
	}
	if allIsSet {
		val := permissions.All.Value
		lineNumber := fileparser.GetLineNumber(permissions.All.Pos)
		if !strings.EqualFold(val, "read-all") && val != "" {
			pdata.results.TokenPermissions = append(pdata.results.TokenPermissions,
				checker.TokenPermission{
					File: &checker.File{
						Path:    path,
						Type:    finding.FileTypeSource,
						Offset:  lineNumber,
						Snippet: val,
					},
					LocationType: &permLoc,
					Value:        &val,
					Type:         checker.PermissionLevelWrite,
					// TODO: Job
				})

			return nil
		}

		pdata.results.TokenPermissions = append(pdata.results.TokenPermissions,
			checker.TokenPermission{
				File: &checker.File{
					Path:    path,
					Type:    finding.FileTypeSource,
					Offset:  lineNumber,
					Snippet: val,
				},
				LocationType: &permLoc,
				Value:        &val,
				Type:         typeOfPermission(val),
				// TODO: Job
			})
	} else /* scopeIsSet == true */ if err := validateMapPermissions(permissions.Scopes,
		permLoc, path, pdata, ignoredPermissions); err != nil {
		return err
	}
	return nil
}

func validateTopLevelPermissions(workflow *ghworkflow.Workflow, path string,
	pdata *permissionCbData,
) error {
	// Check if permissions are set explicitly.
	if workflow.Permissions == nil {
		permLoc := checker.PermissionLocationTop
		pdata.results.TokenPermissions = append(pdata.results.TokenPermissions,
			checker.TokenPermission{
				File: &checker.File{
					Path:   path,
					Type:   finding.FileTypeSource,
					Offset: checker.OffsetDefault,
				},
				LocationType: &permLoc,
				Type:         checker.PermissionLevelUndeclared,
				// TODO: Job
			})

		return nil
	}

	return validatePermissions(workflow.Permissions, checker.PermissionLocationTop, path,
		pdata, map[permission]bool{})
}

func validatejobLevelPermissions(workflow *ghworkflow.Workflow, path string,
	pdata *permissionCbData,
	ignoredPermissions map[permission]bool,
) error {
	for _, job := range workflow.Jobs {
		// Run-level permissions may be left undefined.
		// For most workflows, no write permissions are needed,
		// so only top-level read-only permissions need to be declared.
		if job.Permissions == nil {
			permLoc := checker.PermissionLocationJob
			pdata.results.TokenPermissions = append(pdata.results.TokenPermissions,
				checker.TokenPermission{
					File: &checker.File{
						Path:   path,
						Type:   finding.FileTypeSource,
						Offset: fileparser.GetLineNumber(job.Pos),
					},
					LocationType: &permLoc,
					Type:         checker.PermissionLevelUndeclared,
					Msg:          github.StringPointer(fmt.Sprintf("no %s permission defined", permLoc)),
					// TODO: Job
				})

			continue
		}
		jobIgnoredPermissions := acceptedJobWrites(ignoredPermissions, job, path, pdata)
		err := validatePermissions(job.Permissions, checker.PermissionLocationJob,
			path, pdata, jobIgnoredPermissions)
		if err != nil {
			return err
		}
	}
	return nil
}

// acceptedJobWrites returns ignoredPermissions plus the write permissions that the job
// declares and that are accepted for this job. A write is accepted when:
//   - the maintainer configuration allows it for an action or reusable workflow that the job uses,
//     or for this job of this workflow file, or
//   - the job calls a local reusable workflow that declares the same write. GitHub requires the caller
//     to grant it, and the called workflow gets its own warning where the write is used.
//
// It returns ignoredPermissions unchanged when no write is accepted for the job.
func acceptedJobWrites(ignoredPermissions map[permission]bool, job *ghworkflow.Job, path string,
	pdata *permissionCbData,
) map[permission]bool {
	var jobIgnoredPermissions map[permission]bool
	accept := func(p permission, uses *ghworkflow.String, msg string) {
		if jobIgnoredPermissions == nil {
			jobIgnoredPermissions = maps.Clone(ignoredPermissions)
			if jobIgnoredPermissions == nil {
				jobIgnoredPermissions = make(map[permission]bool)
			}
		}
		jobIgnoredPermissions[p] = true

		// Only log for debugging, like the other accepted writes.
		permLoc := checker.PermissionLocationJob
		pdata.results.TokenPermissions = append(pdata.results.TokenPermissions,
			checker.TokenPermission{
				File: &checker.File{
					Path:    path,
					Type:    finding.FileTypeSource,
					Offset:  fileparser.GetLineNumber(uses.Pos),
					Snippet: uses.Value,
				},
				LocationType: &permLoc,
				Type:         checker.PermissionLevelUnknown,
				Msg:          github.StringPointer(msg),
			})
	}

	for _, aw := range pdata.allowedWrites {
		if !jobDeclaresWrite(job, aw.Permission) {
			continue
		}
		var target *ghworkflow.String
		if aw.Uses != "" {
			target = jobUses(job, aw.Uses)
		} else if path == aw.Workflow && job.ID != nil && strings.EqualFold(job.ID.Value, aw.Job) {
			target = job.ID
		}
		if target != nil {
			accept(permission(aw.Permission), target, fmt.Sprintf(
				"'%s: write' allowed by maintainer configuration for '%s': %s", aw.Permission, aw.Target(), aw.Reason))
		}
	}

	if calledWrites := localCalledWorkflowWrites(job, pdata); calledWrites != nil {
		for _, p := range permissionsOfInterest {
			if calledWrites[p] && jobDeclaresWrite(job, string(p)) {
				accept(p, job.WorkflowCall.Uses, fmt.Sprintf(
					"'%s: write' is declared by the called workflow '%s'", p, job.WorkflowCall.Uses.Value))
			}
		}
	}

	if jobIgnoredPermissions == nil {
		return ignoredPermissions
	}
	return jobIgnoredPermissions
}

// localCalledWorkflowWrites returns the write permissions that the local reusable workflow
// called by the job declares, or nil if the job does not call a local reusable workflow.
// Remote reusable workflows are in other repositories and are not read.
func localCalledWorkflowWrites(job *ghworkflow.Job, pdata *permissionCbData) map[permission]bool {
	if job.WorkflowCall == nil || job.WorkflowCall.Uses == nil ||
		!strings.HasPrefix(job.WorkflowCall.Uses.Value, "./") {
		return nil
	}
	calledPath := strings.TrimPrefix(job.WorkflowCall.Uses.Value, "./")
	if writes, ok := pdata.calledWrites[calledPath]; ok {
		return writes
	}
	writes := readWorkflowWrites(pdata.repoClient, calledPath)
	pdata.calledWrites[calledPath] = writes
	return writes
}

// readWorkflowWrites returns the write permissions that the workflow declares at the top level
// or in any job. If the workflow cannot be read or parsed, it returns an empty set, so the
// caller's writes are reported as usual.
func readWorkflowWrites(rc clients.RepoClient, path string) map[permission]bool {
	writes := make(map[permission]bool)
	if rc == nil {
		return writes
	}
	r, err := rc.GetFileReader(path)
	if err != nil {
		return writes
	}
	defer r.Close()
	content, err := io.ReadAll(r)
	if err != nil {
		return writes
	}
	workflow, _ := ghworkflow.Parse(content)
	if workflow == nil {
		return writes
	}
	addWrites(writes, workflow.Permissions)
	for _, job := range workflow.Jobs {
		addWrites(writes, job.Permissions)
	}
	return writes
}

func addWrites(writes map[permission]bool, perms *ghworkflow.Permissions) {
	if perms == nil {
		return
	}
	if perms.All != nil && strings.EqualFold(perms.All.Value, "write-all") {
		for _, p := range permissionsOfInterest {
			writes[p] = true
		}
		return
	}
	for key, scope := range perms.Scopes {
		if scope != nil && scope.Value != nil && strings.EqualFold(scope.Value.Value, "write") {
			writes[permission(strings.ToLower(key))] = true
		}
	}
}

// jobDeclaresWrite returns true if the job's permissions set the permission to write.
func jobDeclaresWrite(job *ghworkflow.Job, name string) bool {
	if job.Permissions == nil {
		return false
	}
	for key, scope := range job.Permissions.Scopes {
		if strings.EqualFold(key, name) && scope != nil && scope.Value != nil &&
			strings.EqualFold(scope.Value.Value, "write") {
			return true
		}
	}
	return false
}

// jobUses returns the 'uses' value of the job or of one of its steps that
// refers to the action or reusable workflow, or nil if the job does not use it.
// A remote reference matches with any ref; a local reusable workflow matches exactly.
func jobUses(job *ghworkflow.Job, ref string) *ghworkflow.String {
	if job.WorkflowCall != nil && usesMatches(job.WorkflowCall.Uses, ref) {
		return job.WorkflowCall.Uses
	}
	for _, step := range job.Steps {
		if uses := fileparser.GetUses(step); usesMatches(uses, ref) {
			return uses
		}
	}
	return nil
}

func usesMatches(uses *ghworkflow.String, ref string) bool {
	return uses != nil && (uses.Value == ref || strings.HasPrefix(uses.Value, ref+"@"))
}

func isPermissionOfInterest(name permission, ignoredPermissions map[permission]bool) bool {
	for _, p := range permissionsOfInterest {
		_, present := ignoredPermissions[p]
		if strings.EqualFold(string(name), string(p)) && !present {
			return true
		}
	}
	return false
}

func createIgnoredPermissions(workflow *ghworkflow.Workflow, fp string,
	pdata *permissionCbData,
) map[permission]bool {
	ignoredPermissions := make(map[permission]bool)
	if requiresPackagesPermissions(workflow, fp, pdata) {
		ignoredPermissions[permissionPackages] = true
	}
	if requiresContentsPermissions(workflow, fp, pdata) {
		ignoredPermissions[permissionContents] = true
	}
	if isSARIFUploadWorkflow(workflow, fp, pdata) {
		ignoredPermissions[permissionSecurityEvents] = true
	}

	return ignoredPermissions
}

// Scanning tool run externally and SARIF file uploaded.
func isSARIFUploadWorkflow(workflow *ghworkflow.Workflow, fp string, pdata *permissionCbData) bool {
	// TODO: some third party tools may upload directly through their actions.
	// Very unlikely.
	// See https://github.com/marketplace for tools.
	return isAllowedWorkflow(workflow, fp, pdata)
}

func isAllowedWorkflow(workflow *ghworkflow.Workflow, fp string, pdata *permissionCbData) bool {
	//nolint:lll
	allowlist := map[string]bool{
		// CodeQl analysis workflow automatically sends sarif file to GitHub.
		// https://docs.github.com/en/code-security/secure-coding/integrating-with-code-scanning/uploading-a-sarif-file-to-github#about-sarif-file-uploads-for-code-scanning.
		// `The CodeQL action uploads the SARIF file automatically when it completes analysis`.
		"github/codeql-action/analyze": true,

		// Third-party scanning tools use the SARIF-upload action from code-ql.
		// https://docs.github.com/en/code-security/secure-coding/integrating-with-code-scanning/uploading-a-sarif-file-to-github#uploading-a-code-scanning-analysis-with-github-actions
		// We only support CodeQl today.
		"github/codeql-action/upload-sarif": true,

		// allow our own action, which writes sarif files
		// https://github.com/ossf/scorecard-action
		"ossf/scorecard-action": true,

		// Code scanning with HLint uploads a SARIF file to GitHub.
		// https://github.com/haskell-actions/hlint-scan
		"haskell-actions/hlint-scan": true,

		// Code scanning with zizmor uploads a SARIF file to GitHub.
		// https://github.com/zizmorcore/zizmor-action
		"zizmorcore/zizmor-action": true,
	}

	tokenPermissions := checker.TokenPermission{
		File: &checker.File{
			Path:   fp,
			Type:   finding.FileTypeSource,
			Offset: checker.OffsetDefault,
			// TODO: set Snippet.
		},
		Type: checker.PermissionLevelUnknown,
		// TODO: Job
	}

	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			uses := fileparser.GetUses(step)
			if uses == nil {
				continue
			}
			// remove any version pinning for the comparison
			uses.Value = strings.Split(uses.Value, "@")[0]
			if allowlist[uses.Value] {
				tokenPermissions.File.Offset = fileparser.GetLineNumber(uses.Pos)
				tokenPermissions.Msg = github.StringPointer("allowed SARIF workflow detected")
				pdata.results.TokenPermissions = append(pdata.results.TokenPermissions, tokenPermissions)
				return true
			}
		}
	}
	tokenPermissions.Msg = github.StringPointer("not a SARIF workflow, or not an allowed one")
	pdata.results.TokenPermissions = append(pdata.results.TokenPermissions, tokenPermissions)
	return false
}

// A packaging workflow using GitHub's supported packages:
// https://docs.github.com/en/packages.
func requiresPackagesPermissions(workflow *ghworkflow.Workflow, fp string, pdata *permissionCbData) bool {
	// TODO: add support for GitHub registries.
	// Example: https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry.
	match, ok := fileparser.IsPackagingWorkflow(workflow, fp)
	// Print debug messages.
	pdata.results.TokenPermissions = append(pdata.results.TokenPermissions,
		checker.TokenPermission{
			File: &checker.File{
				Path:   fp,
				Type:   finding.FileTypeSource,
				Offset: checker.OffsetDefault,
			},
			Msg:  &match.Msg,
			Type: checker.PermissionLevelUnknown,
		})

	return ok
}

// requiresContentsPermissions returns true if the workflow requires the `contents: write` permission.
func requiresContentsPermissions(workflow *ghworkflow.Workflow, fp string, pdata *permissionCbData) bool {
	return isReleasingWorkflow(workflow, fp, pdata) || isGitHubPagesDeploymentWorkflow(workflow, fp, pdata)
}

// isGitHubPagesDeploymentWorkflow returns true if the workflow involves pushing static pages to GitHub pages.
func isGitHubPagesDeploymentWorkflow(workflow *ghworkflow.Workflow, fp string, pdata *permissionCbData) bool {
	jobMatchers := []fileparser.JobMatcher{
		{
			Steps: []*fileparser.JobMatcherStep{
				{
					Uses: "peaceiris/actions-gh-pages",
				},
			},
			LogText: "candidate GitHub page deployment workflow using peaceiris/actions-gh-pages",
		},
	}

	return isWorkflowOf(workflow, fp, jobMatchers,
		"not a GitHub Pages deployment workflow", pdata)
}

// isReleasingWorkflow returns true if the workflow involves creating a release on GitHub.
func isReleasingWorkflow(workflow *ghworkflow.Workflow, fp string, pdata *permissionCbData) bool {
	jobMatchers := []fileparser.JobMatcher{
		{
			// Python packages.
			// This is a custom Python packaging/releasing workflow based on semantic versioning.
			Steps: []*fileparser.JobMatcherStep{
				{
					Uses: "relekang/python-semantic-release",
				},
			},
			LogText: "candidate python publishing workflow using python-semantic-release",
		},
		{
			// Commonly JavaScript packages, but supports multiple ecosystems
			Steps: []*fileparser.JobMatcherStep{
				{
					Run: "(npx|pnpm|yarn).*semantic-release",
				},
			},
			LogText: "candidate publishing workflow using semantic-release",
		},
		{
			// Go binaries.
			Steps: []*fileparser.JobMatcherStep{
				{
					Uses: "actions/setup-go",
				},
				{
					Uses: "goreleaser/goreleaser-action",
				},
			},
			LogText: "candidate golang publishing workflow",
		},
		{
			// SLSA Go builder. https://github.com/slsa-framework/slsa-github-generator
			Steps: []*fileparser.JobMatcherStep{
				{
					Uses: "slsa-framework/slsa-github-generator/.github/workflows/builder_go_slsa3.yml",
				},
			},
			LogText: "candidate SLSA publishing workflow using slsa-github-generator",
		},
		{
			// SLSA generic generator. https://github.com/slsa-framework/slsa-github-generator
			Steps: []*fileparser.JobMatcherStep{
				{
					Uses: "slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml",
				},
			},
			LogText: "candidate SLSA publishing workflow using slsa-github-generator",
		},
		{
			// Running mvn release:prepare requires committing changes.
			// https://maven.apache.org/maven-release/maven-release-plugin/examples/prepare-release.html
			Steps: []*fileparser.JobMatcherStep{
				{
					Run: ".*mvn.*release:prepare.*",
				},
			},
			LogText: "candidate mvn release workflow",
		},
	}

	return isWorkflowOf(workflow, fp, jobMatchers, "not a releasing workflow", pdata)
}

func isWorkflowOf(workflow *ghworkflow.Workflow, fp string,
	jobMatchers []fileparser.JobMatcher, msg string,
	pdata *permissionCbData,
) bool {
	match, ok := fileparser.AnyJobsMatch(workflow, jobMatchers, fp, msg)

	// Print debug messages.
	pdata.results.TokenPermissions = append(pdata.results.TokenPermissions,
		checker.TokenPermission{
			File: &checker.File{
				Path:   fp,
				Type:   finding.FileTypeSource,
				Offset: checker.OffsetDefault,
			},
			Msg:  &match.Msg,
			Type: checker.PermissionLevelUnknown,
		})

	return ok
}
