// Copyright 2026 OpenSSF Scorecard Authors
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

package config

import (
	"errors"
	"fmt"
	"strings"
)

var errInvalidAllowedWrite = errors.New("token-permissions allowed-write is not valid")

// allowedWritePermissions are the GITHUB_TOKEN permissions that the Token-Permissions check warns about.
var allowedWritePermissions = []string{
	"actions",
	"checks",
	"contents",
	"deployments",
	"packages",
	"security-events",
	"statuses",
}

// TokenPermissions configures the Token-Permissions check.
type TokenPermissions struct {
	// AllowedWrites are job-level write permissions that the check accepts
	// for jobs that use a specific action or reusable workflow, or for specific jobs.
	AllowedWrites []AllowedWrite `yaml:"allowed-writes"`
}

// AllowedWrite accepts a job-level write permission. A rule sets either Uses,
// or Workflow and Job.
type AllowedWrite struct {
	// Permission is the GITHUB_TOKEN permission, e.g. "packages".
	Permission string `yaml:"permission"`
	// Uses is the action or reusable workflow without a ref,
	// e.g. "actions/delete-package-versions" or "./.github/workflows/publish.yml".
	// The rule applies to every job that uses it.
	Uses string `yaml:"uses"`
	// Workflow is the path of a workflow file, e.g. ".github/workflows/publish.yml".
	Workflow string `yaml:"workflow"`
	// Job is the ID of a job in Workflow, e.g. "publish-github".
	Job string `yaml:"job"`
	// Reason tells why the job needs the permission.
	Reason string `yaml:"reason"`
}

// Target returns the action, reusable workflow or job that the rule applies to.
func (aw AllowedWrite) Target() string {
	if aw.Uses != "" {
		return aw.Uses
	}
	return aw.Workflow + ":" + aw.Job
}

func validateTokenPermissions(tp TokenPermissions) error {
	for _, aw := range tp.AllowedWrites {
		if !isAllowedWritePermission(aw.Permission) {
			return fmt.Errorf("%w: unsupported permission %q", errInvalidAllowedWrite, aw.Permission)
		}
		switch {
		case aw.Uses != "" && (aw.Workflow != "" || aw.Job != ""):
			return fmt.Errorf("%w: set either uses, or workflow and job, for permission %q",
				errInvalidAllowedWrite, aw.Permission)
		case aw.Uses != "":
			if strings.Contains(aw.Uses, "@") {
				return fmt.Errorf("%w: uses %q must not include a ref", errInvalidAllowedWrite, aw.Uses)
			}
		case aw.Workflow == "" || aw.Job == "":
			return fmt.Errorf("%w: set uses, or both workflow and job, for permission %q",
				errInvalidAllowedWrite, aw.Permission)
		case !strings.HasPrefix(aw.Workflow, ".github/workflows/"):
			return fmt.Errorf("%w: workflow %q must be a path in .github/workflows/",
				errInvalidAllowedWrite, aw.Workflow)
		}
		if strings.TrimSpace(aw.Reason) == "" {
			return fmt.Errorf("%w: reason is empty for %s on %s", errInvalidAllowedWrite, aw.Permission, aw.Target())
		}
	}
	return nil
}

func isAllowedWritePermission(p string) bool {
	for _, allowed := range allowedWritePermissions {
		if p == allowed {
			return true
		}
	}
	return false
}
